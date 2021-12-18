echo "------------------------------------------------------------"
echo "git clone from https://github.com/apple/coremltools.git"
echo "------------------------------------------------------------"

git clone https://github.com/apple/coremltools.git
cd coremltools

apt install zsh

zsh -i scripts/build.sh

echo "------------------------------------------------------------"
echo "If not install correctly, reopen the termial"
echo "then run command zsh -i scripts/build.sh again"
echo "------------------------------------------------------------"