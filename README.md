# react-native-passkey

[![Build](https://img.shields.io/github/actions/workflow/status/mTRx0/react-native-passkey/main.yml?branch=stable)](https://img.shields.io/github/workflow/status/mTRx0/react-native-passkey/Build) [![Version](https://img.shields.io/npm/v/react-native-passkey)](https://img.shields.io/npm/v/react-native-passkey) [![License](https://img.shields.io/npm/l/react-native-passkey)](https://img.shields.io/npm/l/react-native-passkey)

Native Passkeys on iOS 15.0+ and Android API 28+ using React Native.

> Please note that Android support is still in alpha. ([More info](https://developer.android.com/jetpack/androidx/releases/credentials))
>
> Progress is being tracked [here](https://github.com/f-23/react-native-passkey/issues/2).

## Difference between original repo and this
* Change all base64 encoding to URL-safe and no padding to fit FIDO standard
* Add some missing fields on iOS device
* Works with go-webauthn

## Installation

#### Javascript

For the javascript part of the installation you need to run

```sh
npm install pccr10001/react-native-passkey
```

or

```sh
yarn add pccr10001/react-native-passkey
```

#### Native

For the native part of the installation you need to run

```sh
cd ios && pod install
```

in the root of your React Native project.

---

## Configuration

### iOS

There are iOS specific steps you need to go through in order to configure Passkey support. If you have already set up an associated domain for your application you can skip this step.

#### Set up an associated domain for your application ([More info](https://developer.apple.com/documentation/xcode/supporting-associated-domains))

- You need to associate a domain with your application. On your webserver set up this route:

  ```
  GET https://<yourdomain>/.well-known/apple-app-site-association
  ```

- This route should serve a static JSON object containing your team id and bundle identifier.
  Example (replace XXXXXXXXXX with your team identifier and the rest with your bundle id, e.g. "H123456789.com.mtrx0.passkeyExample"):

  ```json
  {
    "applinks": {},
    "webcredentials": {
      "apps": ["XXXXXXXXXX.YYY.YYYYY.YYYYYYYYYYYYYY"]
    },
    "appclips": {}
  }
  ```

- In XCode under `Signing & Capabilities` add a new Capability of type `Associated Domains`.
  Now add this and replace XXXXXX with your domain (e.g. `apple.com`)
  ```
  webcredentials:XXXXXX
  ```
### Android

The Android specific configuration is similar to iOS. If you have already set up Digital Asset Links for your application you can skip this step.

#### Associate your app with a domain ([More info](https://developer.android.com/training/sign-in/passkeys#add-support-dal))
- You need to associate a domain with your application. On your webserver set up this route:

  ```
  GET https://<yourdomain>/.well-known/assetlinks.json
  ```

- This route should serve a static JSON object containing the following information.
  Example (replace with your data, replace SHA_HEX_VALUE with the SHA256 fingerprints of your Android signing certificate)

  ```json
  [{
    "relation": ["delegate_permission/common.get_login_creds"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example",
      "sha256_cert_fingerprints": [
        SHA_HEX_VALUE
      ]
    }
  }]
  ```

---

## Usage

#### Check if Passkeys are supported

```ts
import { Passkey } from 'react-native-passkey';

// Use this method to check if passkeys are supported on the device

const isSupported: boolean = Passkey.isSupported();
```

#### Creating a new Passkey

```ts
import { Passkey, PasskeyRegistrationResult } from 'react-native-passkey';

// Retrieve a valid FIDO2 attestation request from your server
// The challenge inside the request needs to be a base64 encoded string
// There are plenty of libraries which can be used for this (e.g. fido2-lib)

try {
  // Call the `register` method with the retrieved request in JSON format
  // A native overlay will be displayed
  const result: PasskeyRegistrationResult = await Passkey.register(requestJson);

  // The `register` method returns a FIDO2 attestation result
  // Pass it to your server for verification
} catch (error) {
  // Handle Error...
}
```

#### Authenticating with existing Passkey

```ts
import { Passkey, PasskeyAuthenticationResult } from 'react-native-passkey';

// Retrieve a valid FIDO2 assertion request from your server 
// The challenge inside the request needs to be a base64 encoded string
// There are plenty of libraries which can be used for this (e.g. fido2-lib)

try {
  // Call the `authenticate` method with the retrieved request in JSON format 
  // A native overlay will be displayed
  const result: PasskeyAuthResult = await Passkey.authenticate(requestJson);

  // The `authenticate` method returns a FIDO2 assertion result
  // Pass it to your server for verification
} catch (error) {
  // Handle Error...
}
```

### Security Keys (iOS-only)

You can allow users to register and authenticate using a Security Key (like [Yubikey](https://www.yubico.com/)).

For this just pass an options object containing `{ withSecurityKey: true }` to the `Passkey.authenticate()` or `Passkey.register()` methods.

```ts
const result: PasskeyAuthResult = await Passkey.authenticate(
  requestJson,
  { withSecurityKey: true }
);
```

or

```ts
const result: PasskeyRegistrationResult = await Passkey.register(
  requestJson,
  { withSecurityKey: true }
);
```

---

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

---

## License

MIT
