rm -rf $HOME/MyWork/scan4all_old/release
mv release $HOME/MyWork/scan4all_old/
mv changelog.md $HOME/MyWork/scan4all_old/
cd $HOME/MyWork/scan4all_old/
gh release create $1 -F changelog.md release/*.zip
