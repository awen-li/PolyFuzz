ipcs -m | awk '$2~/[0-9]+/{print $2}' > SHM
cat SHM | while read shm
do
	echo "ipcrm -m $shm"
    ipcrm -m $shm
done