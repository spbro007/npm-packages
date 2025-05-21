import { NativeModule, requireNativeModule } from "expo";

declare class ExpoGoogleAuthModule extends NativeModule {
  launchGoogleAuth(mode: "SIWG" | "GID", webClientId: string): Promise<string>;
  signOut(): Promise<void>;
}

// This call loads the native module object from the JSI.
export default requireNativeModule<ExpoGoogleAuthModule>("ExpoGoogleAuth");
