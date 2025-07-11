#	$OpenBSD: scp3.sh,v 1.5 2023/09/08 06:10:57 djm Exp $
#	Placed in the Public Domain.

tid="scp3"

COPY2=${OBJ}/copy2
DIR=${COPY}.dd
DIR2=${COPY}.dd2

SRC=`dirname ${SCRIPT}`

scpclean() {
	rm -rf ${COPY} ${COPY2} ${DIR} ${DIR2}
	mkdir ${DIR} ${DIR2}
	chmod 755 ${DIR} ${DIR2}
}

# Create directory structure for recursive copy tests.
forest() {
	scpclean
	rm -rf ${DIR2}
	cp ${DATA} ${DIR}/copy
	ln -s ${DIR}/copy ${DIR}/copy-sym
	mkdir ${DIR}/subdir
	cp ${DATA} ${DIR}/subdir/copy
	ln -s ${DIR}/subdir ${DIR}/subdir-sym
}

for mode in $SCP_MODES ; do
	tag="$tid: $mode mode"
	scpopts="-q"
	if test $mode = scp ; then
		scpopts="$scpopts -O -S ${SSH} -F${OBJ}/ssh_proxy"
	else
		scpopts="$scpopts -s -D ${SFTPSERVER}"
	fi

	verbose "$tag: simple copy remote file to remote file"
	scpclean
	SCP_REMOTE_PREFIX=$BUILDDIR/ \
	SCP_REMOTE_PREFIX2=$BUILDDIR/ \
	$SCP $scpopts -3 hostA:${DATA} hostB:${COPY} || fail "copy failed"
	cmp ${DATA} ${COPY} || fail "corrupted copy"

	verbose "$tag: simple copy remote file to remote dir"
	scpclean
	cp ${DATA} ${COPY}
	SCP_REMOTE_PREFIX=$BUILDDIR/ \
	SCP_REMOTE_PREFIX2=$BUILDDIR/ \
	$SCP $scpopts -3 hostA:${COPY} hostB:${DIR} || fail "copy failed"
	cmp ${COPY} ${DIR}/copy || fail "corrupted copy"

	verbose "$tag: recursive remote dir to remote dir"
	forest
	SCP_REMOTE_PREFIX=$BUILDDIR/ \
	SCP_REMOTE_PREFIX2=$BUILDDIR/ \
	$SCP $scpopts -3r hostA:${DIR} hostB:${DIR2} || fail "copy failed"
	diff -r ${DIR} ${DIR2} || fail "corrupted copy"
	diff -r ${DIR2} ${DIR} || fail "corrupted copy"

	verbose "$tag: detect non-directory target"
	scpclean
	echo a > ${COPY}
	echo b > ${COPY2}
	SCP_REMOTE_PREFIX=$BUILDDIR/ \
	SCP_REMOTE_PREFIX2=$BUILDDIR/ \
	$SCP $scpopts -3 hostA:${DATA} hostA:${COPY} hostB:${COPY2}
	cmp ${COPY} ${COPY2} >/dev/null && fail "corrupt target"
done

scpclean
