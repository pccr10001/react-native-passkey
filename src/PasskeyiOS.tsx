import type {
  PasskeyRegistrationResult,
  PasskeyRegistrationRequest,
  PasskeyAuthenticationRequest,
  PasskeyAuthenticationResult,
} from './Passkey';
import { handleNativeError } from './PasskeyError';
import { NativePasskey } from './NativePasskey';

export class PasskeyiOS {
  /**
   * iOS implementation of the registration process
   *
   * @param request The FIDO2 Attestation Request in JSON format
   * @param withSecurityKey A boolean indicating wether a security key should be used for registration
   * @returns The FIDO2 Attestation Result in JSON format
   */
  public static async register(
    request: PasskeyRegistrationRequest,
    withSecurityKey = false
  ): Promise<PasskeyRegistrationResult> {
    // Extract the required data from the attestation request
    const { rpId, challenge, name, userID } =
      this.prepareRegistrationRequest(request);

    try {
      const response = await NativePasskey.register(
        rpId,
        challenge,
        name,
        userID,
        withSecurityKey
      );
      return this.handleNativeRegistrationResult(response);
    } catch (error) {
      throw handleNativeError(error);
    }
  }

  /**
   * Extracts the data required for the attestation process on iOS from a given request
   */
  private static prepareRegistrationRequest(
    request: PasskeyRegistrationRequest
  ): PasskeyiOSRegistrationData {
    return {
      rpId: request.rp.id,
      challenge: this.urlB64toStdB64(request.challenge),
      name: request.user.displayName,
      userID: request.user.id,
    };
  }

  /**
   * Transform the iOS-specific attestation result into a FIDO2 result
   */
  private static handleNativeRegistrationResult(
    result: PasskeyiOSRegistrationResult
  ): PasskeyRegistrationResult {
    return {
      id: this.stdB64toUrlB64(result.credentialID),
      rawId: this.stdB64toUrlB64(result.credentialID),
      type: "public-key",
      response: {
        clientDataJSON: this.stdB64toUrlB64(result.response.rawClientDataJSON),
        attestationObject: this.stdB64toUrlB64(result.response.rawAttestationObject),
      },
    };
  }

  /**
   * iOS implementation of the authentication process
   *
   * @param request The FIDO2 Assertion Request in JSON format
   * @param withSecurityKey A boolean indicating wether a security key should be used for authentication
   * @returns The FIDO2 Assertion Result in JSON format
   */
  public static async authenticate(
    request: PasskeyAuthenticationRequest,
    withSecurityKey = false
  ): Promise<PasskeyAuthenticationResult> {
    try {
      const response = await NativePasskey.authenticate(
        request.rpId,
        this.urlB64toStdB64(request.challenge),
        withSecurityKey
      );
      return this.handleNativeAuthenticationResult(response);
    } catch (error) {
      throw handleNativeError(error);
    }
  }

  /**
   * Transform the iOS-specific assertion result into a FIDO2 result
   */
  private static handleNativeAuthenticationResult(
    result: PasskeyiOSAuthenticationResult
  ): PasskeyAuthenticationResult {
    return {
      id: this.stdB64toUrlB64(result.credentialID),
      rawId: this.stdB64toUrlB64(result.credentialID),
      type: "public-key",
      response: {
        clientDataJSON: this.stdB64toUrlB64(result.response.rawClientDataJSON),
        authenticatorData: this.stdB64toUrlB64(result.response.rawAuthenticatorData),
        signature: this.stdB64toUrlB64(result.response.signature),
        userHandle: this.stdB64toUrlB64(result.userID),
      },
    };
  }

  private static urlB64toStdB64(s: string): string {
    let base64Standard = s.replace(/-/g, '+').replace(/_/g, '/');
    while (base64Standard.length % 4) {
        base64Standard += '=';
    }
    return base64Standard;
  }
  private static stdB64toUrlB64(s: string): string {
    return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, '');
  }
}

interface PasskeyiOSRegistrationData {
  rpId: string;
  challenge: string;
  name: string;
  userID: string;
}

interface PasskeyiOSRegistrationResult {
  credentialID: string;
  response: {
    rawAttestationObject: string;
    rawClientDataJSON: string;
  };
}

interface PasskeyiOSAuthenticationResult {
  credentialID: string;
  userID: string;
  response: {
    rawAuthenticatorData: string;
    rawClientDataJSON: string;
    signature: string;
  };
}
