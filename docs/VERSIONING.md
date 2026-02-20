# Versioning Strategy

Wallet Recovery CLI follows [Semantic Versioning 2.0.0](https://semver.org/).

## Version Format

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

Examples:
- `v1.0.0` - Initial stable release
- `v1.1.0` - New feature added
- `v1.1.1` - Bug fix
- `v2.0.0-alpha.1` - Pre-release for major version

## Version Increments

### MAJOR (X.0.0)
Incremented for breaking changes:
- Removal of commands or flags
- Changes to command behavior that break backward compatibility
- Changes to file formats (recovery kit, encrypted output)
- Changes to cryptographic algorithms or parameters

### MINOR (0.X.0)
Incremented for new features:
- New commands
- New flags on existing commands
- New output formats
- Performance improvements

### PATCH (0.0.X)
Incremented for bug fixes:
- Security fixes
- Bug corrections
- Documentation updates
- Dependency updates (non-breaking)

## Pre-release Versions

For testing before stable releases:
- `alpha.N` - Early testing, unstable
- `beta.N` - Feature complete, testing stability
- `rc.N` - Release candidate, final testing

## Release Process

1. Update `CHANGELOG.md` with release notes
2. Create a git tag: `git tag -a v1.0.0 -m "Release v1.0.0"`
3. Push tag: `git push origin v1.0.0`
4. GitHub Actions automatically builds and publishes release

## Build Metadata

Version is embedded at build time using ldflags:
```bash
go build -ldflags="-X 'main.Version=v1.0.0'" -o recovery
```

Check version with:
```bash
./recovery --version
```

