import Foundation

// Deterministic crash sites. CI (ci/check_crash.py) asserts that the symbolicated crash
// contains these names, this file name and an inlined frame from `trigger`.
//
// Call chain: CrashSite.crash -> CrashPipeline<String>.run -> CrashPipeline.Stage.detonate
//             -> trigger (@inline(__always), so it only exists as an inlined frame).
// `@inline(never)` plus using each callee's result keeps the frames from being merged or
// turned into tail calls in the optimized Release build.

enum CrashKind: String {
    case fatal
    case unwrap
    case nsexception
}

@inline(__always)
func trigger(_ kind: CrashKind, depth: Int) -> Int {
    switch kind {
    case .fatal:
        fatalError("KestrelSpike fatalError at depth \(depth)")
    case .unwrap:
        let value: Int? = depth > 10_000 ? depth : nil
        return value! + depth
    case .nsexception:
        NSException(
            name: .internalInconsistencyException,
            reason: "KestrelSpike NSException at depth \(depth)",
            userInfo: nil
        ).raise()
        return depth
    }
}

struct CrashPipeline<Payload: CustomStringConvertible> {
    let payload: Payload

    struct Stage {
        let depth: Int

        @inline(never)
        func detonate(_ kind: CrashKind) -> Int {
            let result = trigger(kind, depth: depth)
            return result &* 3
        }
    }

    @inline(never)
    func run(_ kind: CrashKind) -> Int {
        let stage = Stage(depth: payload.description.count)
        return stage.detonate(kind) &+ 1
    }
}

enum CrashSite {
    @inline(never)
    static func crash(_ kind: CrashKind) {
        let pipeline = CrashPipeline(payload: ProcessInfo.processInfo.processName)
        let result = pipeline.run(kind)
        print("KESTREL_SPIKE: survived?! \(result)")
    }
}
