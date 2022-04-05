#!/bin/bash
# Basic function

print_usage () {
	echo "Usage: $0 [-S sourceLocationPath] [-I installPath] [-R] \n -S: the source file path should exist.\n -I: the install path shoulw exist\n -R: means download the repo from git. " >&2
	exit 1
}

sourceLocationPath=''
installPath=''
downloadRepo=0
repoPath='https://github.com/CodeIntelligenceTesting/jazzer'

while getopts 'S:RI:' OPTION; do
    case "${OPTION}" in
        S)
            sourceLocationPath=${OPTARG};;
        I)
            installPath=${OPTARG};;
        R)
            downloadRepo=1;;
        *)
            print_usage;;
    esac
done

if [ "${sourceLocationPath}" = "" ]; then
    echo "Source path is empty."
	print_usage
fi

if [ "${installPath}" = "" ]; then
	echo "Install path is empty."
    print_usage
fi

if [ ! -d ${sourceLocationPath} ]; then
    echo "Invalid source path : $sourceLocationPath"
	print_usage
fi

if [ ! -d ${installPath} ]; then
    echo "Invalid install path : $installPath"
	print_usage
fi

cd "${sourceLocationPath}"

if [ "${downloadRepo}" = "1" ]; then
    git clone ${repoPath}
    cd jazzer
fi

bazel build //:jazzer_release
cp ./bazel-bin/jazzer_release.tar.gz ${installPath}/

cd ${installPath}
tar xvf jazzer_release.tar.gz

echo "Compiled jazzer has been installed at: ${installPath}.\n Run '${installPath}/jazzer' for running your jazzer targets."
