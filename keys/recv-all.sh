#! /bin/sh
export keys=`gpg --no-default-keyring --keyring ./phillylinux.gpg --list-keys | grep ^pub | cut -d'/' -f2 | cut -d' ' -f1`
echo $keys
gpg --no-default-keyring --keyring ./phillylinux.gpg  --keyserver subkeys.pgp.net --recv-keys $keys
