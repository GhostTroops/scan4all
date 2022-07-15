gosnmp release process
---

### Steps
* Have a [signingkey](#add-a-signingkey-to-gitconfig) setup.
* File a PR to set a release in the CHANGELOG.
* git [tag-release](#add-a-tag-release-alias-to-gitconfig) X.Y.Z
* In github UI, create the release.
* Copy-n-paste the CHANGELOG entries.
* Publish release.


### add a signingkey to gitconfig
```
[user]
  signingkey = ...
```

### add a tag-release alias to gitconfig
```
[alias]
  tag-release = "!f() { tag=v${1:-$(cat VERSION)} ; git tag -s ${tag} -m ${tag} && git push origin ${tag}; }; f"
```
