import { NativeModule, requireNativeModule } from "expo";

declare class ExpoGoogleAuthModule extends NativeModule {
  launchGoogleAuth(mode: "SIWG" | "GID", webClientId: string): Promise<string>;
  signOut(): Promise<void>;
  authorizeYoutube(scopes: string[], webClientId: string): Promise<string>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ExpoGoogleAuthModule>("ExpoGoogleAuth");
