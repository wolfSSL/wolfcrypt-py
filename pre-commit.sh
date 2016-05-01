#!/bin/sh
#
#
# Our "pre-commit" hook.

# stash modified files not part of this commit, don't test them
echo "\n\nStashing any modified files not part of commit\n\n"
git stash -q --keep-index

# do the commit tests
echo "\n\nRunning commit tests...\n\n"
tox
RESULT=$?

# restore modified files not part of this commit
echo "\n\nPopping any stashed modified files not part of commit\n"
git stash pop -q

[ $RESULT -ne 0 ] && echo "\nOops, your commit failed\n" && exit 1

echo "\nCommit tests passed!\n"
exit 0
