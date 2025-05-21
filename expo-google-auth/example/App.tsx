import { useEvent } from "expo";
import ExpoGoogleAuth from "expo-google-auth";
import {
  Button,
  Pressable,
  SafeAreaView,
  ScrollView,
  Text,
  View,
} from "react-native";

export default function App() {
  return (
    <View
      style={[
        styles.container,
        { justifyContent: "center", alignItems: "center" },
      ]}
    >
      <Pressable onPress={() => ExpoGoogleAuth.launchGoogleAuth("SIWG", process.env.EXPO_PUBLIC_GOOGLE_WEB_CLIENT_ID).catch(e => console.error(e))}>
        <Text>Sign in with Google</Text>
      </Pressable>
    </View>
  );
}

const styles = {
  header: {
    fontSize: 30,
    margin: 20,
  },
  groupHeader: {
    fontSize: 20,
    marginBottom: 20,
  },
  group: {
    margin: 20,
    backgroundColor: "#fff",
    borderRadius: 10,
    padding: 20,
  },
  container: {
    flex: 1,
    backgroundColor: "#eee",
  },
  view: {
    flex: 1,
    height: 200,
  },
};
