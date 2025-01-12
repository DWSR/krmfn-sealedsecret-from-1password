// version contains logic to calculate the version of the application, which is mostly used for logging purposes.
package version

import "runtime/debug"

var buildInfo *debug.BuildInfo

// Version returns the application version according to the compiled-in build info.
func Version() string {
	if buildInfo == nil {
		memoizeBuildInfo()
	}

	var versionStr string

	var dirty bool

	for _, setting := range buildInfo.Settings {
		switch setting.Key {
		case "vcs.revision":
			versionStr = setting.Value
		case "vcs.modified":
			dirty = true
		}
	}

	if dirty {
		versionStr += "-dirty"
	}

	return versionStr
}

func memoizeBuildInfo() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		panic("unable to read build info")
	}

	buildInfo = info
}
