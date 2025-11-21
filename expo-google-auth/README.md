# Expo Google Auth

A React Native Expo module for Google authentication using Google's Identity API and Credential Manager.

Happy to announce public launch on 22 Nov, 2025 😊!

## Installation

```bash
npm install expo-google-auth
```

## Usage

<i>Google Credentials setup required for Android and web client!</i>

#### Method 1 (Latest, Recommended by Google)

```js
import ExpoGoogleAuth from "expo-google-auth";

const gwcId = "<GOOGLE_WEB_CLIENT_ID>";
const idToken = await ExpoGoogleAuth.launchGoogleAuth("GID", gwcId);
```

#### Method 2 (Traditional)

```js
import ExpoGoogleAuth from "expo-google-auth";

const gwcId = "<GOOGLE_WEB_CLIENT_ID>";
const idToken = await ExpoGoogleAuth.launchGoogleAuth("SWIG", gwcId);
```

Now, provide this id token to your auth provider.

Currently, It only supports Android.  
For iOS, rely on [expo-auth-session.](https://docs.expo.dev/versions/latest/sdk/auth-session/)
