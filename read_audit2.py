import json
import collections
import sys
from datetime import datetime
import csv

process_exclude = []
syscall_exclude = []

pid_data = [] # For CSV
path_data = [] # For CSV
syscall_data = [] # For CSV
pid_list = []
dest_data = []
full_data = []
key = "malicious_track"
def makeCsvFile(file_path, header, data):
	with open(file_path, mode="w", newline="") as file:
		writer = csv.DictWriter(file, fieldnames=header)
		writer.writeheader()
		writer.writerows(data)

def collectSyscallArgument(syscallData):
	index = 0
	argumentStr = []
	while True:
		argumentName = "a" + str(index)
		index = index + 1
		if argumentName in syscallData:
			argumentStr.append(syscallData[argumentName])
		else:
			break
	
	return ','.join(argumentStr)

def makeSyscallCSV():
	header = ["seq_id", "pid", "syscall", "key", "arguments", "prev_seq"]
	makeCsvFile("syscall.csv", header, syscall_data)
	'''
	    csv_file_path = "syscall.csv"
    header = ["log_id", "pid", "syscall", "key", "arguments"]
    makeCsvFile(csv_file_path, header, syscall_data)
	'''
	
def getSyscallCSVString(seq, syscallData, processData, key, syscall_map, pid):
	arg = collectSyscallArgument(syscallData)
	exitStr = ""
	if "exit" in syscallData:
		exitStr = syscallData['exit']
	pid = processData['pid']
	syscall = syscallData['syscall']
	prev_seq = ""
	if pid in syscall_map:
		prev_seq = syscall_map[pid]["seq_id"]
	returnData = {"seq_id":seq, "pid": pid, "syscall":syscall, "key":key, "arguments":arg, "prev_seq": prev_seq}
	return returnData

def getSyscallCSVString2(seq, syscallData, processData, key):
	arg = collectSyscallArgument(syscallData)
	exitStr = ""
	if "exit" in syscallData:
		exitStr = syscallData['exit']
	pid = processData['pid']
	syscall = syscallData['syscall']

	returnData = {"seq_id":seq, "pid": pid, "syscall":syscall, "key":key, "arguments":arg, "exit": exitStr}
	return returnData

def getSyscallCSVString3(seq, pid, syscall, key, arg, prev_seq):
	return {"seq_id":seq, "pid": pid, "syscall":syscall, "key":key, "arguments":arg, "prev_seq": prev_seq}

def getDestinationCSVString(seq, destinationData):
	return {"seq_id": seq, "ip" :destinationData["ip"] if "ip" in destinationData else destinationData["path"], "port": destinationData["port"] if "port" in destinationData else ""}

def makeDestinationCSV():
	header = ["seq_id", "ip", "port"]
	makeCsvFile("destination.csv", header, dest_data)

def makeProcessCSV():
	header = ["pid", "ppid", "name", "exePath","processargs", "title", "key"]
	makeCsvFile("pid.csv", header, pid_data)


def getProcessCSVString(processData, key):
	pid = processData['pid']
	ppid = -1
	name = processData['name']
	exePath = processData['executable']
	title = processData['title'] if 'title' in processData else ""
	args = ""
	if "parent" in processData:
		ppid = processData['parent']['pid']
	if "args" in processData:
		args = ",".join(processData["args"])
	returnData = {"pid":pid, "ppid":ppid, "name":name, "exePath":exePath, "title":title, "key": key, "processargs": args.encode("utf-8") }
	return returnData

def makePathCSV():
	header = ["seq_id", "path"]
	makeCsvFile("path.csv", header, path_data)

def getPathCSVString(seq, fileData):
	return {"seq_id": seq, "path":fileData['path']}

def getAllCSVString(timestamp, processString, syscallString, pathString=None, destinationString=None):
	return_map = {}
	return_map["timestamp"] = timestamp
	return_map["seq_id"] = syscallString["seq_id"]
	#return_map["prev_seq"] = syscallString["prev_seq"]
	return_map["pid"] = processString["pid"]
	return_map["ppid"] = processString["ppid"]
	return_map["exePath"] = processString["exePath"] 
	return_map["processArgs"] = processString["processargs"]
	return_map["syscall"] = syscallString["syscall"]
	return_map["arguments"] = syscallString["arguments"]
	return_map["exit"] = syscallString["exit"]
	return_map["fullsyscall"] = f'{syscallString["seq_id"]}: {syscallString["syscall"]}({syscallString["arguments"]}) -> {syscallString["exit"]}'
	if pathString:
		return_map["filepath"] = pathString["path"]
	else:
		return_map["filepath"] = ""
	if destinationString:
		return_map["ip"] = destinationString["ip"]
		return_map["port"] = destinationString["port"]
	else:
		return_map["ip"] = ""
		return_map["port"] = ""
	return return_map
	
def makeFullCSV():
	header = ["timestamp","seq_id", "prev_seq", "pid", "ppid", "exePath", "processArgs", "syscall", "arguments", "exit", "fullsyscall", "filepath", "ip", "port", "auid", "suid", "euid"]
	makeCsvFile("full.csv", header, full_data)

def compareSeq(e):
	return int(e['seq_id'])

def getInitialSequenceMap(filepath):
	f = open(filepath, encoding="utf-8")
	events = []
	for log in f.readlines():
		data = json.loads(log)
		if "tags" in data:
			#print(f"{data}")
			seq = int(data['auditd']['sequence']) #use seq as unique key??
			syscallData = data['auditd']['data']
			processInfo = data['process']
			pid = processInfo['pid']
			timestamp = data["@timestamp"]
			syscallString = getSyscallCSVString2(seq, syscallData, processInfo, key)
			pathString = None
			destString = None
			pid_Csv = getProcessCSVString(processInfo, key)
			pid_pair = (pid_Csv["pid"], pid_Csv["ppid"])
			if pid_pair not in pid_list:
				pid_list.append(pid_pair)
				pid_data.append(pid_Csv)
			if 'file' in data:
				fileData = data['file']
				if 'path' in fileData:
					pathString = getPathCSVString(seq, fileData)
					path_data.append(pathString)
			if 'destination' in data:
				destinationData = data['destination']
				destString = getDestinationCSVString(seq, destinationData)
				dest_data.append(destString)
			full_data_str = getAllCSVString(timestamp,pid_Csv, syscallString, pathString, destString)
			full_data_str['auid'] = ""
			full_data_str['suid'] = ""
			full_data_str['euid'] = ""
			if 'user' in data:
				userData = data['user']
				auditUserId = userData['audit'] if 'audit' in userData else {'id':""}
				eUserId = userData['effective'] if 'effective' in userData else {'id':""}
				sUserId = userData['saved']	if 'saved' in userData else {'id':""}
				full_data_str['auid'] = auditUserId['id']
				full_data_str['suid'] = sUserId['id']
				full_data_str['euid'] = eUserId['id']

			events.append(full_data_str)
			

	events.sort(key=compareSeq)
	return events
				
#	return {"seq_id":seq, "pid": pid, "syscall":syscall, "key":key, "arguments":arg, "prev_seq": prev_seq}

def main():
	
	syscall_map = {} 

	if len(sys.argv) < 2:
		exit("Do not define audit file")
	events = getInitialSequenceMap(sys.argv[1])
	print(len(events))
	for event in events:
		prev_seq = ""
		if event['pid'] in syscall_map:
			prev_seq = syscall_map[event['pid']]["seq_id"]
		syscallString = getSyscallCSVString3(event['seq_id'], event['pid'], event['syscall'], key, event['arguments'], prev_seq)
		syscall_data.append(syscallString)
		syscall_map[event['pid']] = syscallString
		event["prev_seq"] = prev_seq
		full_data.append(event)

	makeSyscallCSV()
	makeProcessCSV()
	makePathCSV()
	makeDestinationCSV()
	makeFullCSV()
if __name__ == '__main__':
	main()
