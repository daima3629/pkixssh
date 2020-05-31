#! /bin/sh


VERSION_PACKAGE=$1
if test -z "$VERSION_PACKAGE" ; then
  echo "usage: $0 [VERSION] " >&1
  exit 1
fi

upd_file() {
  if cmp $1.tmp $1 > /dev/null; then
    rm -f $1.tmp
  else
    mv -v $1.tmp $1
  fi
}


F=version.m4
sed \
  -e "s|SSH_VERSION\],.*|SSH_VERSION], [$VERSION_PACKAGE])|g" \
  $F > $F.tmp
upd_file $F

for F in contrib/*/pkixssh.spec ; do
  sed -e "s|^Version:.*|Version:	$VERSION_PACKAGE|g" $F > $F.tmp
  upd_file $F
done
