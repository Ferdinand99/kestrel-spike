import Sentry
import SwiftUI

enum SpikeError: Error {
    case handled(code: Int)
}

@main
struct KestrelSpikeApp: App {
    init() {
        SentrySDK.start { options in
            options.dsn = "http://publickey@127.0.0.1:9000/1"
            options.debug = true
            options.sendDefaultPii = false
            options.enableCrashHandler = true
            // Relaunching after `simctl terminate` must not produce extra fatal events.
            options.enableWatchdogTerminationTracking = false
            options.releaseName = "net.opland.kestrelspike@1.0+1"
            options.dist = "1"
        }

        // `xcrun simctl launch <udid> net.opland.kestrelspike -crash fatal` puts
        // "crash" = "fatal" into the NSArgumentDomain of UserDefaults.
        if let raw = UserDefaults.standard.string(forKey: "crash"),
           let kind = CrashKind(rawValue: raw) {
            SentrySDK.configureScope { $0.setTag(value: raw, key: "crash_kind") }
            print("KESTREL_SPIKE: crashing with \(raw) in 2s")
            // Give the SDK time to finish installing its crash handlers.
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                CrashSite.crash(kind)
            }
        } else {
            print("KESTREL_SPIKE: normal launch, sending handled error")
            SentrySDK.capture(error: SpikeError.handled(code: 42))
        }
    }

    var body: some Scene {
        WindowGroup {
            Text("Kestrel spike")
        }
    }
}
