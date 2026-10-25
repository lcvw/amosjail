# Escape probes, built on the test Mac. sleeper-gta is the outside target:
# debuggable (get-task-allow), so unsandboxed same-uid code *can* take it over.
all: probe net sti sleeper-gta
probe net sti: %: %.c
	$(CC) -O2 -o $@ $<
sleeper-gta: sleeper.c gta.plist
	$(CC) -O2 -o $@ sleeper.c && codesign -f -s - --entitlements gta.plist $@ 2>/dev/null
clean:
	rm -f probe net sti sleeper-gta
