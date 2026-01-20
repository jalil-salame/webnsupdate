release-plz --version
declare -ra release_args=(--verbose --registry=git-salame-cl --forge=gitea)

case "$FORGEJO_REF" in
# On main create a release
refs/heads/main)
	# Generate a release (won't do anything if the current version is already published)
	echo "Creating release"
	release-plz release "${release_args[@]}"

	# Create a release PR (will bump the version)
	echo "Creating release PR"
	release-plz release-pr "${release_args[@]}"
	;;
# Not on main, do a dry-run
*)
	# Update package version and changelog
	echo "Updating package version and changelog"
	release-plz update "${release_args[@]}"

	# Do a dry-run
	echo "Release dry-run"
	release-plz release "${release_args[@]}" --dry-run --allow-dirty
	;;
esac
