#!/bin/sh
echo "------------------------------------------------------------"
echo "git clone from https://github.com/mongodb/mongo-python-driver"
echo "------------------------------------------------------------"
git clone https://github.com/mongodb/mongo-python-driver.git
cd mongo-python-driver/
python setup.py install
echo "------------------------------------------------------------"
echo "mongo-python-driver installed"
echo "------------------------------------------------------------"

while true
do
read -r -p "Do you want to test it now? It might cost 3 mins [Y/n]:" input
    case $input in
    [yY][eE][sS]|[yY])

    python setup.py test
    echo "------------------------------------------------------------"
    echo "test done"
    echo "------------------------------------------------------------"
    exit 1
    ;;

    [nN][oO]|[nN])
    echo "------------------------------------------------------------"
    echo "use 'python setup.py test' for testing in the future"
    echo "------------------------------------------------------------"
    exit 1
    ;;
*)

    echo "Invalid Input"
    ;;
    esac
done
