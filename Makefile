# Common tasks. The app is an Xcode project over the Core Swift package;
# everything here also works from Xcode itself.

DERIVED := build/DerivedData
APP := $(DERIVED)/Build/Products/Release/Twotbit.app

.PHONY: app debug test test-release run clean icon

# Builds the release app into build/DerivedData/Build/Products/Release.
app:
	xcodebuild -project Twotbit.xcodeproj -scheme Twotbit -configuration Release -derivedDataPath $(DERIVED) build

debug:
	xcodebuild -project Twotbit.xcodeproj -scheme Twotbit -configuration Debug -derivedDataPath $(DERIVED) build

# Runs the wallet engine's tests: crypto, wallet, chain, filters, wire,
# storage and end-to-end syncs against in-process mock nodes.
test:
	swift test --package-path Core

test-release:
	swift test --package-path Core -c release

# Opens the release app; pass flags with ARGS, as ARGS="-net signet".
run: app
	open $(APP) --args $(ARGS)

icon:
	swift Scripts/make-icon.swift App/Assets.xcassets/AppIcon.appiconset

clean:
	rm -rf build Core/.build
