import { HttpStatusCode } from "@bitwarden/common/enums";
import { Utils } from "@bitwarden/common/platform/misc/utils";

import { Account } from "./account";
import { BinaryReader } from "./binary-reader";
import { Chunk } from "./chunk";
import { ClientInfo } from "./client-info";
import { CryptoUtils } from "./crypto-utils";
import { OobResult } from "./oob-result";
import { OtpMethod } from "./otp-method";
import { OtpResult } from "./otp-result";
import { Parser } from "./parser";
import { ParserOptions } from "./parser-options";
import { Platform } from "./platform";
import { RestClient } from "./rest-client";
import { Session } from "./session";
import { SharedFolder } from "./shared-folder";
import { Ui } from "./ui";

const PlatformToUserAgent = new Map<Platform, string>([
  [Platform.Desktop, "cli"],
  [Platform.Mobile, "android"],
]);

const KnownOtpMethods = new Map<string, OtpMethod>([
  ["googleauthrequired", OtpMethod.GoogleAuth],
  ["microsoftauthrequired", OtpMethod.MicrosoftAuth],
  ["otprequired", OtpMethod.Yubikey],
]);

export class Client {
  constructor(private parser: Parser, private cryptoUtils: CryptoUtils) {}

  async openVault(
    username: string,
    password: string,
    clientInfo: ClientInfo,
    ui: Ui,
    options: ParserOptions
  ): Promise<Account[]> {
    const lowercaseUsername = username.toLowerCase();
    const [session, rest] = await this.login(lowercaseUsername, password, clientInfo, ui);
    try {
      const blob = await this.downloadVault(session, rest);
      const key = await this.cryptoUtils.deriveKey(
        lowercaseUsername,
        password,
        session.keyIterationCount
      );

      let privateKey: Uint8Array = null;
      if (session.encryptedPrivateKey != null && session.encryptedPrivateKey != "") {
        privateKey = await this.parser.parseEncryptedPrivateKey(session.encryptedPrivateKey, key);
      }

      return this.parseVault(blob, key, privateKey, options);
    } finally {
      await this.logout(session, rest);
    }
  }

  private async parseVault(
    blob: Uint8Array,
    encryptionKey: Uint8Array,
    privateKey: Uint8Array,
    options: ParserOptions
  ): Promise<Account[]> {
    const reader = new BinaryReader(blob);
    const chunks = this.parser.extractChunks(reader);
    if (!this.isComplete(chunks)) {
      throw "Blob is truncated or corrupted";
    }
    return await this.parseAccounts(chunks, encryptionKey, privateKey, options);
  }

  private async parseAccounts(
    chunks: Chunk[],
    encryptionKey: Uint8Array,
    privateKey: Uint8Array,
    options: ParserOptions
  ): Promise<Account[]> {
    const accounts = new Array<Account>();
    let folder: SharedFolder = null;
    for (const chunk of chunks) {
      if (chunk.id === "ACCT") {
        const key = folder == null ? encryptionKey : folder.encryptionKey;
        const account = await this.parser.parseAcct(chunk, key, folder, options);
        if (account != null) {
          accounts.push(account);
        }
      } else if (chunk.id === "SHAR") {
        folder = await this.parser.parseShar(chunk, encryptionKey, privateKey);
      }
    }
    return accounts;
  }

  private isComplete(chunks: Chunk[]): boolean {
    if (chunks.length > 0 && chunks[chunks.length - 1].id === "ENDM") {
      const okChunk = Utils.fromBufferToUtf8(chunks[chunks.length - 1].payload);
      return okChunk === "OK";
    }
    return false;
  }

  private async login(
    username: string,
    password: string,
    clientInfo: ClientInfo,
    ui: Ui
  ): Promise<[Session, RestClient]> {
    const rest = new RestClient();
    rest.baseUrl = "https://lastpass.com";

    /*
    1. First we need to request PBKDF2 key iteration count.
    
    We no longer request the iteration count from the server in a separate request because it
    started to fail in weird ways. It seems there's a special combination or the UA and cookies
    that returns the correct result. And that is not 100% reliable. After two or three attempts
    it starts to fail again with an incorrect result.
    
    So we just went back a few years to the original way LastPass used to handle the iterations.
    Namely, submit the default value and if it fails, the error would contain the correct value:
    <response><error iterations="5000" /></response>
    */
    let keyIterationCount = 100_100;

    let response: Document = null;
    let session: Session = null;

    // We have a maximum of 3 retries in case we need to try again with the correct domain and/or
    // the number of KDF iterations the second/third time around.
    for (let i = 0; i < 3; i++) {
      // 2. Knowing the iterations count we can hash the password and log in.
      // On the first attempt simply with the username and password.
      response = await this.performSingleLoginRequest(
        username,
        password,
        keyIterationCount,
        new Map<string, any>(),
        clientInfo,
        rest
      );

      session = this.extractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
      if (session != null) {
        return [session, rest];
      }

      // It's possible we're being redirected to another region.
      const server = this.getOptionalErrorAttribute(response, "server");
      if (server != null && server.trim() != "") {
        rest.baseUrl = "https://" + server;
        continue;
      }

      // It's possible for the request above to come back with the correct iteration count.
      // In this case we have to parse and repeat.
      const correctIterationCount = this.getOptionalErrorAttribute(response, "iterations");
      if (correctIterationCount == null) {
        break;
      }

      try {
        keyIterationCount = parseInt(correctIterationCount);
      } catch {
        throw (
          "Failed to parse the iteration count, expected an integer value '" +
          correctIterationCount +
          "'"
        );
      }
    }

    // 3. The simple login failed. This is usually due to some error, invalid credentials or
    // a multifactor authentication being enabled.
    const cause = this.getOptionalErrorAttribute(response, "cause");
    if (cause == null) {
      throw this.makeLoginError(response);
    }

    const optMethod = KnownOtpMethods.get(cause);
    if (optMethod != null) {
      // 3.1. One-time-password is required
      session = await this.loginWithOtp(
        username,
        password,
        keyIterationCount,
        optMethod,
        clientInfo,
        ui,
        rest
      );
    } else if (cause === "outofbandrequired") {
      // 3.2. Some out-of-bound authentication is enabled. This does not require any
      // additional input from the user.
      session = await this.loginWithOob(
        username,
        password,
        keyIterationCount,
        this.getAllErrorAttributes(response),
        clientInfo,
        ui,
        rest
      );
    }

    // Nothing worked
    if (session == null) {
      throw this.makeLoginError(response);
    }

    // All good
    return [session, rest];
  }

  private async loginWithOtp(
    username: string,
    password: string,
    keyIterationCount: number,
    method: OtpMethod,
    clientInfo: ClientInfo,
    ui: Ui,
    rest: RestClient
  ): Promise<Session> {
    let passcode: OtpResult = null;
    switch (method) {
      case OtpMethod.GoogleAuth:
        passcode = ui.provideGoogleAuthPasscode();
        break;
      case OtpMethod.MicrosoftAuth:
        passcode = ui.provideMicrosoftAuthPasscode();
        break;
      case OtpMethod.Yubikey:
        passcode = ui.provideYubikeyPasscode();
        break;
      default:
        throw "Invalid OTP method";
    }

    if (passcode == OtpResult.cancel) {
      throw "Second factor step is canceled by the user";
    }

    const response = await this.performSingleLoginRequest(
      username,
      password,
      keyIterationCount,
      new Map<string, string>([["otp", passcode.passcode]]),
      clientInfo,
      rest
    );

    const session = this.extractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
    if (session == null) {
      throw this.makeLoginError(response);
    }
    if (passcode.rememberMe) {
      await this.markDeviceAsTrusted(session, clientInfo, rest);
    }
    return session;
  }

  private async loginWithOob(
    username: string,
    password: string,
    keyIterationCount: number,
    parameters: Map<string, string>,
    clientInfo: ClientInfo,
    ui: Ui,
    rest: RestClient
  ): Promise<Session> {
    const answer = this.approveOob(username, parameters, ui, rest);
    if (answer == OobResult.cancel) {
      throw "Out of band step is canceled by the user";
    }

    const extraParameters = new Map<string, any>();
    if (answer.waitForOutOfBand) {
      extraParameters.set("outofbandrequest", 1);
    } else {
      extraParameters.set("otp", answer.passcode);
    }

    let session: Session = null;
    for (;;) {
      // In case of the OOB auth the server doesn't respond instantly. This works more like a long poll.
      // The server times out in about 10 seconds so there's no need to back off.
      const response = await this.performSingleLoginRequest(
        username,
        password,
        keyIterationCount,
        extraParameters,
        clientInfo,
        rest
      );

      session = this.extractSessionFromLoginResponse(response, keyIterationCount, clientInfo);
      if (session != null) {
        break;
      }

      if (this.getOptionalErrorAttribute(response, "cause") != "outofbandrequired") {
        throw this.makeLoginError(response);
      }

      // Retry
      extraParameters.set("outofbandretry", "1");
      extraParameters.set("outofbandretryid", this.getErrorAttribute(response, "retryid"));
    }

    if (answer.rememberMe) {
      await this.markDeviceAsTrusted(session, clientInfo, rest);
    }
    return session;
  }

  private approveOob(username: string, parameters: Map<string, string>, ui: Ui, rest: RestClient) {
    const method = parameters.get("outofbandtype");
    if (method == null) {
      throw "Out of band method is not specified";
    }
    switch (method) {
      case "lastpassauth":
        return ui.approveLastPassAuth();
      case "duo":
        return this.approveDuo(username, parameters, ui, rest);
      case "salesforcehash":
        return ui.approveSalesforceAuth();
      default:
        throw "Out of band method " + method + " is not supported";
    }
  }

  private approveDuo(
    username: string,
    parameters: Map<string, string>,
    ui: Ui,
    rest: RestClient
  ): OobResult {
    return parameters.get("preferduowebsdk") == "1"
      ? this.approveDuoWebSdk(username, parameters, ui, rest)
      : ui.approveDuo();
  }

  private approveDuoWebSdk(
    username: string,
    parameters: Map<string, string>,
    ui: Ui,
    rest: RestClient
  ): OobResult {
    // TODO: implement this
    return OobResult.cancel;
  }

  private async markDeviceAsTrusted(session: Session, clientInfo: ClientInfo, rest: RestClient) {
    const parameters = new Map<string, string>([
      ["uuid", clientInfo.id],
      ["trustlabel", clientInfo.description],
      ["token", session.token],
    ]);
    const response = await rest.postForm(
      "trust.php",
      parameters,
      null,
      this.getSessionCookies(session)
    );
    if (response.status == HttpStatusCode.Ok) {
      return;
    }
    this.makeError(response);
  }

  private async logout(session: Session, rest: RestClient) {
    const parameters = new Map<string, any>([
      ["method", PlatformToUserAgent.get(session.platform)],
      ["noredirect", 1],
    ]);
    const response = await rest.postForm(
      "logout.php",
      parameters,
      null,
      this.getSessionCookies(session)
    );
    if (response.status == HttpStatusCode.Ok) {
      return;
    }
    this.makeError(response);
  }

  private async downloadVault(session: Session, rest: RestClient): Promise<Uint8Array> {
    const endpoint =
      "getaccts.php?mobile=1&b64=1&hash=0.0&hasplugin=3.0.23&requestsrc=" +
      PlatformToUserAgent.get(session.platform);
    const response = await rest.get(endpoint, null, this.getSessionCookies(session));
    if (response.status == HttpStatusCode.Ok) {
      const b64 = await response.text();
      return Utils.fromB64ToArray(b64);
    }
    this.makeError(response);
  }

  private getSessionCookies(session: Session) {
    return new Map<string, string>([["PHPSESSID", encodeURIComponent(session.id)]]);
  }

  private getErrorAttribute(response: Document, name: string): string {
    const attr = this.getOptionalErrorAttribute(response, name);
    if (attr != null) {
      return attr;
    }
    throw "Unknown response schema: attribute " + name + " is missing";
  }

  private getOptionalErrorAttribute(response: Document, name: string): string {
    const error = response.querySelector("response > error");
    if (error == null) {
      return null;
    }
    const attr = error.attributes.getNamedItem(name);
    if (attr == null) {
      return null;
    }
    return attr.value;
  }

  private getAllErrorAttributes(response: Document): Map<string, string> {
    const error = response.querySelector("response > error");
    if (error == null) {
      return null;
    }
    const map = new Map<string, string>();
    for (const attr of Array.from(error.attributes)) {
      map.set(attr.name, attr.value);
    }
    return map;
  }

  private extractSessionFromLoginResponse(
    response: Document,
    keyIterationCount: number,
    clientInfo: ClientInfo
  ): Session {
    const ok = response.querySelector("response > ok");
    if (ok == null) {
      return null;
    }
    const sessionId = ok.attributes.getNamedItem("sessionid");
    if (sessionId == null) {
      return null;
    }
    const token = ok.attributes.getNamedItem("token");
    if (token == null) {
      return null;
    }

    const session = new Session();
    session.id = sessionId.value;
    session.keyIterationCount = keyIterationCount;
    session.token = token.value;
    session.platform = clientInfo.platform;
    const privateKey = ok.attributes.getNamedItem("privatekeyenc");
    if (privateKey != null && privateKey.value != null && privateKey.value.trim() != "") {
      session.encryptedPrivateKey = privateKey.value;
    }

    return session;
  }

  private async performSingleLoginRequest(
    username: string,
    password: string,
    keyIterationCount: number,
    extraParameters: Map<string, any>,
    clientInfo: ClientInfo,
    rest: RestClient
  ) {
    const hash = await this.cryptoUtils.deriveKeyHash(username, password, keyIterationCount);

    const parameters = new Map<string, any>([
      ["method", PlatformToUserAgent.get(clientInfo.platform)],
      ["xml", "2"],
      ["username", username],
      ["hash", Utils.fromBufferToHex(hash.buffer)],
      ["iterations", keyIterationCount],
      ["includeprivatekeyenc", "1"],
      ["outofbandsupported", "1"],
      ["uuid", clientInfo.id],
      // TODO: Test against the real server if it's ok to send this every time!
      ["trustlabel", clientInfo.description],
    ]);
    for (const [key, value] of extraParameters) {
      parameters.set(key, value);
    }

    const response = await rest.postForm("login.php", parameters);
    if (response.status == HttpStatusCode.Ok) {
      const text = await response.text();
      const domParser = new window.DOMParser();
      return domParser.parseFromString(text, "text/xml");
    }
    this.makeError(response);
  }

  private makeError(response: Response) {
    // TODO: error parsing
    throw "HTTP request to " + response.url + " failed with status " + response.status + ".";
  }

  private makeLoginError(response: Document): string {
    const error = response.querySelector("response > error");
    if (error == null) {
      return "Unknown response schema";
    }

    const cause = error.attributes.getNamedItem("cause");
    const message = error.attributes.getNamedItem("message");

    if (cause != null) {
      switch (cause.value) {
        case "unknownemail":
          return "Invalid username";
        case "unknownpassword":
          return "Invalid password";
        case "googleauthfailed":
        case "microsoftauthfailed":
        case "otpfailed":
          return "Second factor code is incorrect";
        case "multifactorresponsefailed":
          return "Out of band authentication failed";
        default:
          return message?.value ?? cause.value;
      }
    }

    // No cause, maybe at least a message
    if (message != null) {
      return message.value;
    }

    // Nothing we know, just the error element
    return "Unknown error";
  }
}
