#!/bin/bash

#############global variables##############
#this is a gloablly unique counter that is used to differentiate response diff files
reqcount=0

#by default the header value is set to nill
headertoset=''

# function definitions


##### END OF FUNCTION DEFINITIONS SECTION ######	
#remove any residual files left lying about: 
rm cleanscannerinputlist.txt 2>/dev/null
rm 0 2>/dev/null
rm dump 2>/dev/null
rm dumpfile 2>/dev/null
rm search.txt 2>/dev/null
rm scannerinputlist.txt 2>/dev/null
rm 1scannerinputlist.txt 2>/dev/null
rm search.txt 2>/dev/null
rm dumpfile 2>/dev/null
rm dump 2>/dev/null
rm 2scannerinputlist.txt 2>/dev/null
rm dump.txt.txt 2>/dev/null
rm parameters_to_skip.txt 2>/dev/null
rm payloads.txt 2>/dev/null
rm outputheader.txt 2>/dev/null
rm search.txt 2>/dev/null


#initialise some of the logic flags to false:
n=false
s=false
q=false
m=false
e=false
h=false
x=false
u=false
curlproxy=""
P=false
b=false
C=false
f=false
o=false
D=false
G=false
H=false
Z=false
Y=false
V=false
U=false
O=false
K=false
J=false
N=false
g=false
m=false
p=false
w=false
z=false

#################command switch parser section#########################
#available: g,y (problematic),z

while getopts l:c:t:nsqehx:d:bu:P:v:L:M:Q:I:T:C:r:WS:ABjYfoD:FGHRZVUOKJENakm:pwyz: namer; do
    case $namer in 
    l)  #path to burp log to parse
        burplog=$OPTARG
        ;;
    m) # multi-log analysis mode
	secondburplog=$OPTARG
	m=true  
	;;
    D)  #back end dbms
	D=true
        dbms=$OPTARG
        ;;
    o)  #OVERRIDE NON TESTING OF LOGIN
	o=true
        ;;
    c)  #cookie to add to requests
        cookie=$OPTARG
        ;;
    t)  #target hostname/ip
        uhostname=$OPTARG
        ;;    
    T)  #url to test a connection to
        T=true
	testurl=$OPTARG
        ;;
    n)  #use numeric injection payloads
        n=true
        ;;
    f)  #fulsh out the session file
        f=true
        ;;
    s)  #use string injection payloads
        s=true
        ;;
    q)  #use quote injection payloads 
        q=true
        ;;
    r)  #set the range value
       r=true
	rangerVal=$OPTARG
        ;;
    e)  #use SQL time delay injection payloads 
        e=true
        ;;
    b)  #use OS command injection delay payloads
        b=true
        ;;     
    h)  #help!
        h=true
        ;;
    x) # time delay duration
        x=true
	timedelay=$OPTARG
        ;;
    d) # default error string used to ID a default error page
        d=true
	ErrorString=$OPTARG
        ;;
    j) # default error string used to ID a default error page
        j=true
	 ;;
    A) # null mode
        A=true
        ;;  
    B) # CRLF mode
        B=true
        ;;  
    v) # set a curl proxy
        v=true
	curlproxy=$OPTARG
        ;;
    P) # parse the log and create an input file
        P=true
	parseOutputFile=$OPTARG
        ;;    
    I) # Use an input file file, not a burp log
        I=true
	inputFile=$OPTARG
        ;;    
    L) # Session cookie liveness check GET URL
        L=true
	canaryRequest=$OPTARG
        ;;
    M) # Session cookie liveness check search string
        M=true
	canaryRequestSearchString=$OPTARG
        ;;
    Q) # Session cookie liveness check search string
        Q=true
	resumeline=$OPTARG
        ;;    
    C) # Custom payload list
        C=true
	custompayloadlist=$OPTARG
        ;;
    W) # Method swapping mode
        W=true
        ;;
    S) # parameters to skip
        S=true
	parameterstoskip=$OPTARG
        ;;
#	Y) # parameters to skip
#    	Y=true
#	;;
    F) # Dont skip params that have already been scanned
        F=true
	;;
    G) # Dont perform the normal connection test
        G=true
	;;
    a) # add a header
        a=true
	headertoadd=$OPTARG
	;;
    R) # RESTful parameters mode. F is set to true to override parameter skipping - as we cannot detect a page, we cannot apply param skipping 
        R=true
	F=true  
	;;
    Z) # DEBUG mode activated
	Z=true  
	;;
    Y) # Filter Evasion SQL comments for spaces
	Y=true  
	;;
    V) # Filter Evasion double URL encoding
	V=true  
	;;
    U) # Filter Evasion cAmEl cAsE
	U=true  
	;;
    O) # Filter Evasion MYSQL comments in SQL commands
	O=true  
	;;
    K) # ??? wtf -K does not work???
	K=true  
	;;
    J) # Filter Evasion nesting 'select' => 'selselectect'
	J=true  
	;;
    E) # Filter Evasion '=' => 'like'
	E=true  
	;;
    N) # Filter Evasion Intermediary chars ' ' => '%2f%2a%0B%0C%0D%0A%09%2a%2f'
	N=true  
	;;
    p) # hash + noise + newline
	p=true  
	;;
    w) # comment + newline
	w=true  
	;;
    z) # Multi Byte Quote
	z=true  
	;;
    esac
done

# help mode activated
if [ true = "$h" ] || ["$1" == ""] 2>/dev/null ; then
	echo "$0 - A wrapper for curl written in bash :-)"
	echo "Written by Toby Clarke"
	echo "Multi-log analysis concept provided by Toby Shelswell"
	echo "Required arguments:"
	echo "  -t <host> Target hostname or IP address. No trailing slash."
	echo "AND one of:"
	echo "  -l <burplog> Path to the burp log file that will be parsed for requests. NOT a burp state file, but a log created in Burp > options > logging"
#	echo "  -I <input file to use> Parse an input file, not a burp log. Input files can be created using the -P switch"
	echo "OR just:" 
	echo "  -T <test URL> Test mode: define a test URL to attempt a connection to. Also may require -c <cookie> to connect"
#	echo "OR:"
#	echo "  -P <input file to create> Parse mode: create an input file from a burp log. This can subsequently be scanned using the -I option. Also requires -l <burplog> to parse"	
	echo "Various extra options:"
	echo "  -r <numeric range value> Alter the range value. This is the number of numeric values requested 'either side' of the detected value. By default the range is set to 5, resulting in requests from 995 to 1005 for a detected value of 1000."
#	echo "  -W HTTP Method Swapping mode: GET requests are converted to POSTs and vice-versa. These new requests are tested IN ADDITION to the original."
	echo "  -m <second burp log> Multi-log analysis mode. Walk the application with two different users and feed in two burp log files. The Manipulator will scan for parameter manipulation using parameter values from from walks 1 and 2 and diffing the responses. Note that this is not limited to numeric values."
	echo "  -c <cookie> Add cookies. Enclose in single quotes: -c 'foo=bar'. Multiple cookies must be defined without spaces: -c 'foo=bar;sna=fu'"
	echo "  -a <headername:headervalue> Add a header like this (basic HTTP auth) example: -a 'Authorization: Basic d2ViZ29hdDp3ZWJnb2F0'"	
	echo "  -d <default error string> Define a detection string (inside double quotes) to identify a default error page"
	echo "  -v <http://proxy:port> Define a proxy. Currently, I crash burp. Dont know why."
	echo "  -L <URL of session liveness check page> Conduct an access check on a given page to determine the session cookie is valid"	
        echo "  -M <Search string> String to search for in session liveness check page. Replace spaces with periods: 'Welcome user Bob' should be 'Welcome.user.Bob'"
        echo "  -Q <Request number> Resume a halted scan at a given request number"        
	echo "  -T <Test URL> Test mode: define a test URL to attempt a connection to. Also may require -c <cookie> to connect"
	echo "  -S <file containing parameters to skip, each parameter on a seperate line> Define one or many parameters NOT to scan"
	echo "  -o Override the typical behaviour of excluding any requests which include the following phrases: logoff, logout, exit, signout, delete, signoff"
#	echo "  -F Override the typical behaviour of skipping parameters that have already been scanned. Increases scan time, but scans every parameter of every request"
	echo "  -Z DEBUG mode - very verbose output - useful for script debugging"
	echo "Some examples:"
	echo "Scan based on a burp log:"
	echo "  $0 -t http://www.foo.bar -l example-burp.log"
	echo "Using multi-log analysis mode to identify parameter values to test with:"
	echo "  $0 -l ./logs/user-1.log -m ./logs/user-2.log"
	echo "Runtime hints: CNTRL+c to skip to the end of the current loop iteration, CNTRL+z to stop scanning altogether, re-run with the same values to resume an incomplete scan"	
	exit
fi

#a header has been specified
if [[ true == "$a" ]] ; then
	echo "Adding header $headertoadd"
	headertoset="$headertoadd"
fi

#error handling
if [[ true == "$m" && "$burplog" == "" ]] ; then
	echo "FATAL: I need a second burplog for Multi-log mode." >&2
	echo "-l <burplog> -m <second burplog>">&2
	exit
fi

#error handling
if [[ true == "$m" && "$r" == true ]] ; then
	echo "FATAL: Range value has no meaning for multi-log mode." >&2
	exit
fi

#no burplog or input file specified:
if [[ "$burplog" == "" && "$inputFile" == "" && "$testurl" == "" ]] ; then
	echo "FATAL: I need a burplog or an input file to parse." >&2
	echo "-l <burplog> or -I <input file>">&2
	exit
fi

#no hostname provided:
if [[ "$uhostname" == "" && "$burplog" == "" && "$testurl" == "" ]]; then
	echo "FATAL: I need a hostname (no trailing slash)." >&2
	echo "-t <host>">&2
	exit
fi

#hostname has a trailing slash:
lastchar="${uhostname: -1}"
if [[ "$lastchar" == "/" ]] ; then
	echo "FATAL: hostname $uhostname has a trailing slash. Please re-run the scan and remove the slash at the end of the hostname."
	exit
fi

# this fixes weird behaviour if no cookie value is given by setting a stupid cookie
if [[ "$cookie" == "" ]]; then
	echo "Cookie not provided. Setting cookie to foo=bar" >&2
	cookie="foo=bar"
fi

safefilename=`echo $uhostname-$(date)| replace " " "-" | replace "//" "" | replace ":" "."`
safehostname=`echo $uhostname | replace " " "-" | replace "//" "" | replace ":" "."`

#this just sets curls -k option which means that it will handle cert errors without borking
protocol=`echo $uhostname| cut -d ":" -f 1` 
if [[ "$protocol" == "https" ]]; then
	httpssupport="-k"
else
	httpssupport=""	
fi

#unless we are using an .input file, the safelogname should be the $burplog path value
if [[ true != "$I" ]]; then
	safelogname=`echo $burplog | replace " " "" | replace "/" "-" | replace ":" "-" | replace '\' ''| replace "." "_" `
else
	safelogname=`echo $inputFile | replace " " "" | replace "/" "-" | replace ":" "-" | replace '\' ''| replace "." "_" `
fi

###check for previous scan reports
includereports=0
fooa=`ls ./output/$safelogname$safehostname* 2>/dev/null | wc -l`
if [[ "$fooa" != "0" ]] ; then
	echo "Prior report files found:"
	fooa=`ls ./output/$safelogname$safehostname*`
	echo "$fooa"
	echo -n "Enter y at the prompt to include prior reports in output or n to ignore them: "
	read choice
	if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
		echo "Including prior reports"
		includereports=1		
	else 
		echo "Ignoring prior reports"
	fi
fi

### session file checking / creation code ###
# the idea here is that the user should be happy killing and resuming a scan.
# this is facilitated by saving the scan progress (specifically the request 
# or "URL number" last scanned) in a session file and then checking for the 
# presence of this file whenever a scan is launched

if [ true != "$Q" ] ; then
	#echo "Checking for session file."
	if [ true = "$f" ] ; then
		rm ./session/$safelogname.$safehostname.session.txt 2>/dev/null
	fi
	session=''
	session=`cat ./session/$safelogname.$safehostname.session.txt 2>/dev/null`
	if [[ "$session" != "" ]]; then
		echo "Session file found at ./session/$safelogname.$safehostname.session.txt"
		echo "Looks like you've scanned this host before." 	
		echo "Do you want to resume from the last URL scanned: ($session)?"
		echo -n "Enter y at the prompt to resume from URL $session or n to start from the first URL: "
		read choice
		if [[ "$choice" == "y" ]]; then
			echo "Resuming scan from URL $session"		
			resumeline=$session
			Q=true
		else 
			echo "Starting from the first URL"
			resumeline=0
		fi
		# put your input file recovery code here 
		#echo "Session file found at ./session/$safelogname.$safehostname.session.txt"
		#./session/$safelogname.$safehostname.input
		#echo "Checking for .input file"
		inputCheck=`wc ./session/$safelogname.$safehostname.input 2>/dev/null` 
		if [[ "$inputCheck!" != "" ]] ; then
			echo "Input file found at ./session/$safelogname.$safehostname.input"
			echo -n "Enter n at the prompt to create a fresh .input file or y to use the previously created .input file: "
			read choice
			if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
				echo "Re-using the .input file at ./session/$safelogname.$safehostname.input"		
				I=true
				inputFile="./session/$safelogname.$safehostname.input"
			else 
				echo "Creating a fresh .input file from the burp log"
			fi
		fi
	else 
		echo "Session file not found. Creating ./session/$safelogname.$safehostname.session.txt and starting from the first URL"
	fi
else
	echo "Resuming scan at request $resumeline"
fi

rm ./aggoutputlog.txt 2>/dev/null
rm ./alertmessage.txt 2>/dev/null
	
#################wget spider section#########################

#wget --mirror http://192.168.194.129/ -o ./wgetlog.txt -d --spider

#wget log parsing section#

#get="GET "
#post="POST "
#question="\?"
#N=0
#begin="---request begin---"
#end="---request end---"

#captureflag=0

#cat ./wgetlog.txt | while read LINE ; do
#	if [[ $LINE =~ $begin ]]; then
#		captureflag=1
#	fi
#	if [[ $LINE =~ $end ]]; then
#		captureflag=0
#	fi
#	if [ $captureflag == 1 ]; then
#		captureflag=0
#	fi


#################burplog parser section#########################

########BURPLOG PARSING SECTION############

#if the user hasn't provided an input file, or a test URL, they must have provided a burp log to parse: 
if [[ true != "$I" && true != "$T" ]] ; then
	rm 1scannerinputlist.txt 2>/dev/null
	rm scannerinputlist.txt 2>/dev/null
	rm ./multipartlist.txt 2>/dev/null

	burplines=`wc -l $burplog | cut -d " " -f 1`
	echo "Parsing burp log $burplog with $burplines lines"  
	if [[ $burplines == "" || $burplines == "0" ]] ; then
		echo "Fatal Error: Burp log provided has no lines: please check your settings."
		exit
	fi
		
	########BURPLOG ANALYSIS SECTION############

	N=0
	lineflag=0
	fileflag=0
	captureflag=0
	#the below get re-used later on in the code - dont change them
	#for some reason it seemed easier to define these and then match against the definition
	equalcheck="======================================================"
	get="GET "
	get2="GET"
	post="POST "
	post2="POST" 
	question="\?"
	colon=":"
	equals="="
	#initialise some variables:
	postflag=0
	postdataflag=0
	postURIflag=0
	multipartpost=0
	searchformultipartdata=0
	rm ./partlist.txt 2>/dev/null
	# this next block of code is a 'for' loop over the list of entries in the $burplog txt file.
	# its purpose is to translate a burp log into .input format, which is a list of lines like this:
	# GET /foobar.php?sna=fu 
	# if you use a 'for' loop in bash it treats spaces as delimiters by default - 'while | read' is 
	# one way to get bash to treat each line as a whole regardless of spaces
	cat $burplog | while read LINE ; do
		if [ $lineflag == 2 ]; then
			#two =========== lines gone past: this is the trigger to start capturing data"
			captureflag=1
			counter=$((counter+1))
		fi
	
		if [ $lineflag == 3 ]; then
			#three =========== lines gone past: this is the trigger to stop capturing data"
			captureflag=0		
			#reset the flag that counts the number of ============= lines that have passed by:
			lineflag=0
			#echo -n "."
			#we output multipart post details here as we are at the end of the request: 
			if [ $multipartpost == 1 ]; then
				out=`cat ./partlist.txt | tr -d "[:cntrl:]"`
				multipartpost=0
				searchformultipartdata=0
				#this is to chop off the trailing '&'
				len=${#out}
				lenminus1=$((len-1))
				mparams=${out:0:lenminus1}

				echo "POST" $outer"???"$mparams  >> 1scannerinputlist.txt
				echo "POST" $outer"???"$mparams 
				rm ./partlist.txt
			fi
 
		fi
		if [ $captureflag == 1 ]; then
		# we are capturing burp log info:
		# first question: is it a POST or GET request?
			#if [[ $LINE =~ $get && $LINE =~ $question ]]; then       # modified the below to allow URLs without ?'s for restful mode
			if [[ $LINE =~ $get ]]; then
				# GET detected the next line takes a line like:"
				# GET /foobar.asp?snafu=yep HTTP/1.1
				# and outputs:
				# GET /foobar.asp?snafu=yep				
				getline=`echo "$LINE" | cut -d " " -f 1,2`
				echo $getline >> 1scannerinputlist.txt
			fi
			#this code includes support for POST URI parameters:
			if [[ $LINE =~ $post && $LINE =~ $question ]]; then      
			# added the line below to allow URLs without ?'s for restful mode
			#if [[ $LINE =~ $post ]]; then             # this lead to errors tho so removed it again and restored the original
				# POST with URI parameters detected. Store in the 'outer' variable, a line such as:"
				# /foobar.asp?snafu=yep				
				outer=`echo "$LINE" | cut -d " " -f 2`;
				postflag=1
				postURIflag=1			
			fi
			if [[ $LINE =~ $post && !($LINE =~ $question) ]]; then
				# 'Normal' POST detected:
				# as before with the URI POST, we chop off the 'POST ' and 'HTTP/1.1' feilds either 
				# side of the URI, to store in the 'outer' variable something like:
				# /foobar.asp
				outer=`echo "$LINE" | cut -d " " -f 2`
				# raise the postflag: we are hunting for the postdata now:
				postflag=1
			fi
			if [ $postflag == 1 ]; then
				#this is my lame postdata matching condition:
				#the post data has an "=" and DOESENT have a ":" (keeps the headers away from the door...)
				#TODO sharpen this test up a bit!
				if [[ $LINE =~ $equals && !($LINE =~ $colon) && !($LINE =~ $question) && !($LINE =~ $equalcheck) ]]; then
 					if [ $postURIflag == 1 ]; then
						echo "POST" $outer"??"$LINE  >> 1scannerinputlist.txt
						# In the case of a POST with URI parameters, POST body parameters are preceded with ??, like this:
						# POST /foobar.aspx?URIparam=1??bodyparam=2
						postURIflag=0
					else
						echo "POST" $outer"?"$LINE  >> 1scannerinputlist.txt
						# In the case of a 'normal' POST request, POST body parameters are preceded with ?, like this:
						# POST /foobar.aspx?bodyparam=2
						
					fi
				#reset the post flag in preparation for parsing the next request:
				postflag=0
				fi
			fi
			#if we find a line like: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryOXye4QTitIZotFdn
			if [[ $LINE =~ "Content-Type" && $LINE =~ "multipart" && $LINE =~ "boundary" ]]; then
				#set the multipartpostflag for this request
				multipartpost=1
				#marker=`echo "$LINE" | cut -d "=" -f 2`
					
			fi
			if [ $multipartpost == 1 ]; then
				#if we find a line like: Content-Disposition: form-data; name="input1"
				if [[ $LINE =~ "Content-Disposition" && $LINE =~ "form-data" ]] ; then
					#store the name value such as input1 in the example line above
					#printf -v str 'Hello World\n===========\n'
					multipartname=`echo $LINE | cut -d "=" -f 2 | replace '"' ''`
					#now we are hunting for the multipart data, so set the flag:
					searchformultipartdata=1
					#store the current line number as the multipart data is in 2 lines:
					thelinenumer=$N
				fi
			fi
			#if we are hunting for the multipart data:
			if [ $searchformultipartdata == 1 ]; then
				#echo "MATCH"					
				#get the stored line number from above, and add 2:
				checkval=$((thelinenumer+2))
				#echo "compare: $N with: $checkval"
				#compare this value with the current line number:
				if [ $N == $checkval ]; then
					#if they match, grab the value of this line - its the multipart data:
					multipartval=($LINE)
					#stop hunting for multipart data:
					searchformultipartdata=0
					#concatenate the multipart name and data values to a text file 
					# - there could be one or more name value pairs: 
					#multiparams="$multipartname$multipartval$multiparams"
					echo $multipartname >> ./partlist.txt
					echo "="$multipartval  >> ./partlist.txt
					echo "&" >> ./partlist.txt
				fi 
			fi
		fi
		
		#if [ true = "$Z" ] ; then echo "Line $N = $LINE" ;fi
		if [[ $LINE =~ $equalcheck ]]; then
			# lineflag increments with long lines of '=' characters. burp logs use three of these lines to capture a single request.
			# when lineflag=1 we have a request, when lineflag=2 we capture the next line, when lineflag=3 we have seen the whole of the request: 
			# ======================================================
			# 1:50:18 PM  http://192.168.182.136:80
			# ======================================================
			# POST /dvwa/vulnerabilities/exec/ HTTP/1.1
			# Host: 192.168.182.136
			# Referer: http://192.168.182.136/dvwa/vulnerabilities/exec/
			# Cookie: security=high; PHPSESSID=67pq8ivtjaj485sbvck5fs8c87; acopendivids=phpbb2,redmine; acgroupswithpersist=nada
			# Content-Length: 20
			#	
			# ip=qwe&submit=submit
			# ======================================================
			lineflag=$((lineflag+1))
		fi
		N=$((N+1))
	done
	
	
	#cat 1scannerinputlist.txt
	#exit
	rm 2scannerinputlist.txt 2>/dev/null

	# if Method swapping has been specified, add a GET for each POST and vice-versa:
	# btw, if a POST request is normal (i.e. no URI params), then the body params are preceded by a single '?'
	# however, if a POST request has URI parameters, then these are preceded by a '?', while the POST body params are preceded by '??'
	if [ true = "$W" ] ; then
		cat 1scannerinputlist.txt | while read i;
			do methodical=`echo $i | cut -d " " -f 1`
			if [[ "$methodical" =~ "POST" ]]; then
				echo GET `echo $i | cut -d " " -f2 | replace '??' '&'` >> 2scannerinputlist.txt 
				echo POST `echo $i | cut -d " " -f2` >> 2scannerinputlist.txt
			else
				echo GET `echo $i | cut -d " " -f2` >> 2scannerinputlist.txt 
				echo POST `echo $i | cut -d " " -f2` >> 2scannerinputlist.txt
				#the above line causes GET params to be passed as POST body params, otherwide they'd be treated as POST URI params	
			fi
		done
	else 
		cp 1scannerinputlist.txt 2scannerinputlist.txt	
	fi

#cat 2scannerinputlist.txt
#exit
	#sort uniq the list and also clean out log entries that you dont want to be scanning:
	# note that this is now sort -r. hopefully this will reverse the sort list and cause POSTS to be scanned first :)
	cat 2scannerinputlist.txt | grep -v "\(\.png\|\.jpg\|\.css\|\.bmp\|\.gif\)" | sort -r | uniq > 3scannerinputlist.txt

	#need some code to double up the post reqs with params:
	#this is to support scanning of POST URIs
	#where a POST with URIs is found, first time it'll scan the POST URIs, next time it'll scan the POST data params. (or the other way round.. i cant remember)
	#hence we need duplicates of POST requests that have POST URIs.
	#this has to be done after the | sort | uniq
	cat 3scannerinputlist.txt | while read LINE; do
		echo -n "."
		echo $LINE >> scannerinputlist.txt
		#modded this to exclude multipart post forms: /foo.asp???bar=1:
		if [[ $LINE =~ $post && $LINE =~ $question$question && !($LINE =~ $question$question$question) ]]; then
			echo $LINE >> scannerinputlist.txt
		fi
	done

	#TODO: investigate this and the below if statement. 
	#get rid of any requests without ?'s unless F:
	if [[ true != "$R" ]]; then # ...unless F (override param skipping) is set:
		cat scannerinputlist.txt | while read LINE; do
			echo -n "."
			if [[ $LINE =~ $question ]]; then
				echo $LINE >> 4scannerinputlist.txt
			else
				uyrgf=1
			fi
		done
		cp 4scannerinputlist.txt scannerinputlist.txt
	fi
	
	#get rid of any requests WITH ?'s IF F:
	if [[ true == "$R" ]]; then # ...if F (override param skipping) is set:
		cat scannerinputlist.txt | while read LINE; do
			echo -n "."
			if [[ $LINE =~ $question ]]; then
				uyrgf=1
			else
				echo $LINE >> 4scannerinputlist.txt
			fi
		done
		cp 4scannerinputlist.txt scannerinputlist.txt
	fi
		
	#as 1scannerinputlist.txt (and its friends) is accumulative by nature, it must be cleared down 
	rm 1scannerinputlist.txt 2>/dev/null	
	rm 2scannerinputlist.txt 2>/dev/null	
	rm 3scannerinputlist.txt 2>/dev/null
	rm 4scannerinputlist.txt 2>/dev/null
fi
### done parsing the burplog - the output is in scannerinputlist.txt ###


#OPTIONAL URL connection testing routine:
if [ true = "$T" ] ; then
	echo "Testing connection to $testurl" 
	testresult=`curl $testurl -v -o testoutput.html --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w %{http_code}:%{size_download}`
	testresultstatus=`echo $testresult | cut -d ":" -f 1`
	testresultlength=`echo $testresult | cut -d ":" -f 2`
	echo "The status code was "$testresultstatus 
	echo "The response length was "$testresultlength
	echo "The output has been saved as testoutput.html" 
	exit
fi

#An input file has been specified:
if [ true = "$I" ] ; then
	rm scannerinputlist.txt 2>/dev/null
	echo "Parsing input file" $inputFile
	cat "$inputFile" | while read quack; do
		echo $quack >> scannerinputlist.txt
	done
	echo "Parsed input file $inputFile" 
fi

#as both the below lists are accumulative ny nature, they must first be cleared down before they are used:
rm cleanscannerinputlist.txt 2>/dev/null
rm exceptionlist.txt 2>/dev/null

if [ false = "$o" ] ; then
	#identify any risky request URLs
	cat scannerinputlist.txt | while read quack; do
		textsearch=`echo $quack | grep -i "\(logoff\|login\|logout\|exit\|signout\|delete\|signoff\|password\)"`
		if [[ "$textsearch" != "" ]] ; then
			echo $quack >> exceptionlist.txt
		else
			echo $quack >> cleanscannerinputlist.txt
			echo -n "."
		fi
	done
else
	cp scannerinputlist.txt cleanscannerinputlist.txt;
fi

# the user wants to parse the burplog and create a .input file
if [ true = "$P" ] ; then
	cat cleanscannerinputlist.txt | while read quack; do
		echo $quack >> $parseOutputFile
	done
	echo "Input file $parseOutputFile created"
	echo "The following potentially risky URLs (if any) were removed: " >> urltested.txt
	cat exceptionlist.txt >> urltested.txt
	echo "	*	*	*	*	*	*" >> urltested.txt
	echo "The following URLs were added: " >> urltested.txt
	cat cleanscannerinputlist.txt >> urltested.txt
	cat urltested.txt
	rm urltested.txt 2>/dev/null	
	exit
fi

entries=`wc -l cleanscannerinputlist.txt | cut -d " " -f 1`

#cat cleanscannerinputlist.txt

echo ""
echo "Scan list created with $entries entries" 
echo "Saving a .input file (including risky requests) to: ./session/$safelogname.$safehostname.input" 
cp scannerinputlist.txt ./session/$safelogname.$safehostname.input

rm scannerinputlist.txt 2>/dev/null


#echo "debugGOT  HERE"
#exit

exceptions=`cat exceptionlist.txt 2>/dev/null`
if [[ "$exceptions" != "" ]] ; then
	cat exceptionlist.txt 2>/dev/null 
	echo "The URLs listed above are potentially risky and will be excluded from scanning. Run the scan again using the -o option to include them."
	echo -n "Enter y to continue or n to quit: "
	read keyinput
		if [[ "$keyinput" == "n" ]] ; then
		exit;
	fi
fi

rm exceptionlist.txt 2>/dev/null

#MANDATORY URL connection testing routine:
if [ false = "$G" ] ; then
#check to ensure a target has been defined:
	if [[ $uhostname == "" ]]
		then echo "Fatal: No target defined. Please specify a target using -t."
		exit
	fi
	#message in red
	echo "Attempting a test connection to $uhostname" 
	testresult=`curl $uhostname -v $curlproxy $httpssupport -H "$headertoset" -w %{http_code}:%{size_download}`
	testresultstatus=`echo $testresult | cut -d ":" -f 1`
	testresultlength=`echo $testresult | cut -d ":" -f 2`
	#echo "The status code was "$testresultstatus 
	echo ""
	echo "" 
	if [[ $testresultstatus == "000" ]]
		then echo "No data returned on connection: is the server up? Check your settings or set the -G flag to skip the connection check."
		exit
	else
		echo "Connection looks good."
	fi		
fi

#this IF statement creates list of params to skip based on a user-supplied list, or using the default list.
rm ./parameters_to_skip.txt 2>/dev/null
if [ true = "$S" ] ; then					
	cat $parameterstoskip | while read quack; do
		echo $quack >> parameters_to_skip.txt
	done
else 
	cat ./payloads/default_parameters_to_skip.txt | while read quack; do
		echo $quack >> parameters_to_skip.txt
	done
fi

#################scanner section#########################
K=0

mainrequester()
{
# beginning of main request function
# this section is written confusingly:
# first we do clean & evil GET requests
# then we do clean & evil POST requests
# but POST requests are split out three ways: normal POST, POST URI params, POST data params
# also, for POSTs, we only send one good request per URL instead of one per parameter

if [ true = "$Z" ] ; then echo "DEBUG! Entering REQUEST PHASE"; fi
sessionStorage=`cat ./session/$safelogname.$safehostname.sessionStorage.txt 2>/dev/null`
if [[ $method != "POST" ]]; then #we're doing a get - simples
	if [[ "$sessionStorage" = 0 ]] ; then
		#write set sessionStorage to 1 to prevent clean requests being sent for each param:
		sessionStorage=1
		echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
		# send a 'normal' request
		and1eq1=`curl $i -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`
		if [ true = "$Z" ] ; then resp=`echo $and1eq1 | cut -d ":" -f 1`; time=`echo $and1eq1 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
		echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt
		echo "Testing URL $K of $entries $method $i"
	fi
	echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"
	#send an evil get requst
	and1eq2=`curl $r -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`
	if [ true = "$Z" ] ; then echo "Request: $r";fi
	if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
	# right, thats it for clean and evil GET requests. now POSTs:
else	# we're doing a POST - not so simple...
	# we only need to send a clean request if we are doing time diffing and we havent already sent one for this URL
	# TODO move the below IF to the next level up:
	# it should encapsulate both clean GETs and clean POSTS, not just clean POSTS
	# NOTE the below IF never gets executed, EXCEPT when doing timedelay or command injection.
	# This is because length diff testing requests are sent by the EVIL send (the following IF)
	# which commences with the comment "send an 'evil' POST request"
	if [[ "$sessionStorage" == 0 && true = "$e" || true = "$b" ]] ; then
		# send a 'normal' POST request
		if (($firstPOSTURIURL>0)) ; then
			if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
				if [ $multipartPOSTURL != 1 ] ; then
					and1eq1=`curl -d "$static" $uhostname$page"?"$params -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`
				fi
				if [ true = "$Z" ] ; then echo "Request: $uhostname$page"?"$params"??"$static";fi
				if [ true = "$Z" ] ; then resp=`echo $and1eq1 | cut -d ":" -f 1`; time=`echo $and1eq1 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
				#write set sessionStorage to 1 to prevent clean requests being sent for each param:
				sessionStorage=1
				echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
				echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt
				echo "Testing URL $K of $entries POST $uhostname$page?$params??$static" 	
			fi
			if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
				and1eq1=`curl -d "$params" $uhostname$page -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`;
				if [ true = "$Z" ] ; then echo "Request: $uhostname$page"?"$params";fi
				if [ true = "$Z" ] ; then resp=`echo $and1eq1 | cut -d ":" -f 1`; time=`echo $and1eq1 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
				sessionStorage=1
				echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
				echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt
				echo "Testing URL $K of $entries POST $uhostname$page??$params" 
			fi
		elif [ "$multipartPOSTURL" == 1 ] ; then #we are in the land of multipart forms. here be dragons
				mparam=`echo "--form $params" | replace "&" " --form " `
				and1eq2=`curl $uhostname$page $mparam -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`
		else #just a normal POST:
			and1eq1=`curl -d "$params" $uhostname$page -o dump --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`
			if [ true = "$Z" ] ; then resp=`echo $and1eq1 | cut -d ":" -f 1`; time=`echo $and1eq1 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
			#write set sessionStorage to 1 to prevent clean requests being sent for each param:
			sessionStorage=1
			echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
			echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt
			echo "Testing URL $K of $entries POST $uhostname$page?$params" 		
		fi	
	fi
	# send an 'evil' POST request
	if (($firstPOSTURIURL>0)) ; then
		if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
			and1eq2=`curl -d "$static" $uhostname$page"?"$output -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`
			if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
			echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"	
		fi
		if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
			and1eq2=`curl -d "$output" $uhostname$page -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`
			if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
			echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"
		fi
	elif [ "$multipartPOSTURL" == 1 ] ; then #we are in multipart form mode
		#mparam=$(echo "--form \"$output\"" | replace "&" "\" --form \"")
		#printf -v str 'Hello World\n===========\n'
		echo -n "--form \""$output\" | replace '&' '" --form "' > ./foo.txt
		#TODO: re-implement the -H "$headertoset" option in the below:
		and1eq2="`eval curl $uhostname$page "\`cat ./foo.txt\`" -o dumpfile --cookie $cookie $curlproxy $httpssupport -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`"
		if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi  
		echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"
	else #just a normal evil POST:
		echo "$method URL: $K/$entries Param ("$((paramflag + 1 ))"/"$arraylength")": $paramtotest "Payload ("$payloadcounter"/"$totalpayloads"): $payload"
		and1eq2=`curl -d "$output" $uhostname$page -o dumpfile --cookie $cookie $curlproxy $httpssupport -H "$headertoset" -w "%{http_code}:%{size_download}:%{time_total}" 2>/dev/null`
		if [ true = "$Z" ] ; then resp=`echo $and1eq2 | cut -d ":" -f 1`; time=`echo $and1eq2 | cut -d ":" -f 3`; echo "DEBUG! STATUS: $resp TIME: $time";fi
	fi
fi
#end of request function
}

####### scanning loop #############

#this line makes sure we have specified a payload type
#if [[ true = "$n" || true = "$s" || true = "$e" || true = "$b" || true = "$q" || true = "$r" || true = "$C" ]] ; then

#message in red
echo -e '\E[31;48m'"\033[1mScan commenced\033[0m"
tput sgr0 # Reset attributes.

### new scanning engine ###
##BEGINING OF PER-URL LOOP:
firstPOSTURIURL=0
# the firstPOSTURIURL flag handles situations where POST requests have URI parmeters and has three states: 
# 0 no postURI params (this must be a GET or a normal POST)
# 1 postURI param detected, fuzz the postURI params, send the post data params as a static string
# 2 postURI param detected, fuzz the post data params, send the postURI params as a static string

firstrunflag=0	
vulnerable=0

echo "" > ./session/$safelogname.$safehostname.oldURL.txt
echo "" > ./session/$safelogname.$safehostname.oldparamlist.txt

cat cleanscannerinputlist.txt | while read i; do
	#default the multipartPOSTURL flag down to 0 - most requests are 'normal'
	multipartPOSTURL=0
	if [ true = "$Z" ] ; then echo "DEBUG! Starting outerloop iteration" ;fi
	methodical=`echo $i | cut -d " " -f 1`
	if [[ $i =~ $question$question && "$methodical" =~ "POST" && $i =~ !($question$question$question) ]] ; then
		#increment the firstPOSTURIURL flag: 
		firstPOSTURIURL=$((firstPOSTURIURL+1)) 
	fi
	#this is for multipart POST forms:
	if [[ $i =~ $question$question$question && "$methodical" =~ "POST" ]] ; then
		multipartPOSTURL=1 
		echo "INFO: Multipart form detected"
	fi

	if [ true = "$Z" ] ; then echo "DEBUG! firstPOSTURIURL: $firstPOSTURIURL" ; fi
	if [ true = "$Z" ] ; then echo "DEBUG! i: $i" ;fi
	K=$((K+1)); #this is a request counter
	continueflag=0
	alreadyscanned=0
	#had to store some loop params in text files as they kept getting cleared down
	#have to initialise these values at the start of the loop: 
	sessionStorage=0
	echo $sessionStorage > ./session/$safelogname.$safehostname.sessionStorage.txt
	and1eq1=0
	echo $and1eq1 > ./session/$safelogname.$safehostname.and1eq1.txt

	if [ true = "$L" ] ; then
		# session liveness check was requested
		checkpage=`curl $canaryRequest -o dump.txt --cookie $cookie $curlproxy $httpssupport -H "$headertoset"`
		cat dump.txt 2>/dev/null | egrep -o $canaryRequestSearchString > search.txt
		search=`cat search.txt`
		if [[ $search != "" ]]
			then echo "Session is valid"
		else	
			echo "Halting as session is invalid. Resume at request number "$K
			break
		fi
	fi
	# resume routine to allow users to resume a scan from a given request number
	if [ true = "$Q" ] ; then
		if (($K<$resumeline))
			then echo "Skipping request number "$K
			continue 3
		fi
	fi

	method=`echo $i | cut -d " " -f 1`
	
	#work out what the page value is. for a firstPOSTURIURL value of 2, set the page to be the page AND the postURI params
	#for everything else, the page is the page... 
	if [ $firstPOSTURIURL == 2 ] ; then 
		page=`echo $i | cut -d " " -f 2 | cut -d "?" -f 1,2`
	else
		page=`echo $i | cut -d " " -f 2 | cut -d "?" -f 1`
	fi


	#this section determines the parameters we will fuzz
	#it outputs stringofparams which is a string that takes a querystring like 'q=1&f=2&n=3' and converts it to 'q=1 f=2 n=3'.
	#TODO: the below does not account for normal POST requests? investigate? 
	#this branch is for RESTful params	
	if [[ true == "$R" ]]; then
		if (($firstPOSTURIURL>0)) ; then
			if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
				params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
				static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
			fi
			if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
				params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
				static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
			fi
		else #we are dealing with a simple GET request
			params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 1 | cut -d "/" -f 2,3,4,5,6,7,8,9,10,11,12 | replace "/" "="`
		fi
		#echo "DEBUG $i"
		#echo "DEBUG $uhostname"
		#echo "debug i "$i;				
						
		stringofparams=`echo $params | tr "&" " "`		
	else # normal scan not RESTful #work out the params that will be fuzzed in this loop iteration:
		if [ true = "$Z" ] ; then echo "DEBUG! NOT RESTFUL PARAMS"; fi
		if (($firstPOSTURIURL>0)) ; then
			if [ $firstPOSTURIURL == 1 ] ; then #we want to fuzz the POSTURI params, NOT the data
				params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
				static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
			fi
			if [ $firstPOSTURIURL == 2 ] ; then #we want to fuzz the POST data params, NOT the POSTURI params
				params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
				static=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
			fi
		elif [ $multipartPOSTURL == 1 ] ; then #multipart post request:
			params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 4`
		else #we are dealing with a simple GET request
			params=`echo $i | cut -d " " -f 2 | cut -d "?" -f 2`
		fi
		
		#echo "debug static "$i;				
		#echo "debug params "$params;				
		stringofparams=`echo $params | tr "&" " "`
		
		#echo `echo $stringofparams` >> ./session/$safelogname.$safehostname.siteanalysis.txt	
	fi	
	if [ true = "$Z" ] ; then echo "DEBUG! params: "$params; fi
	if [ true = "$Z" ] && [ $firstPOSTURIURL != "0" ] ; then echo "DEBUG! static: "$static; fi
	if [ true = "$Z" ] ; then echo "DEBUG! stringofparams: $stringofparams" ;fi
	
	#code that compares the current URL and params for comparison against the old URL - this can be used to skip params already scanned
	#newURL=`echo $i | cut -d "?" -f 1| cut -d " " -f2`
	newURL=`echo $i | cut -d "?" -f 1`
	newParams=$stringofparams
	oldURL=`cat ./session/$safelogname.$safehostname.oldURL.txt`
	#oldParams=`cat ./session/$safelogname.$safehostname.oldParams.txt`

	#if the current and last urls dont match, clear down the lists
	#we want these lists to grow across a given URL, but re-start
	#when a new URL comes along
	if [[ true != "$F" ]]; then # ...unless F (override param skipping) is set:
		if [[ "$oldURL" == "$newURL" ]] ; then
			if [[ "$firstrunflag" == 0 || "$K" == "$entries" ]] ; then
				echo "------------------" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				echo "$newURL" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				for dfg in $stringofparams; do
					echo `echo $dfg | cut -d "=" -f1` >> ./session/$safelogname.$safehostname.siteanalysis.txt
				done
				firstrunflag=1
				#this branch is taken for the first and last URLs, otherwise these wouldent be captured in the siteanalysis log
			fi
		else
			if [[ "$firstrunflag" == 0 || "$K" == "$entries" ]] ; then
				echo "------------------" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				echo "$newURL" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				for dfg in $stringofparams; do
					echo `echo $dfg | cut -d "=" -f1` >> ./session/$safelogname.$safehostname.siteanalysis.txt
				done
				firstrunflag=1
				#this branch is taken for the first and last URLs, otherwise these wouldent be captured in the siteanalysis log
			else
				#this branch is taken when a new URL comes along
				#the below writes out the old URL and paramlist info to the siteanalysis log
				
				echo "------------------" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				echo "$oldURL" >> ./session/$safelogname.$safehostname.siteanalysis.txt
				cat ./session/$safelogname.$safehostname.oldparamlist.txt >> ./session/$safelogname.$safehostname.siteanalysis.txt
				#the below clears away the old paramlist
				echo "" > ./session/$safelogname.$safehostname.oldparamlist.txt
			fi
		fi
	fi
	#paramsarray stores the query string params
	paramsarray=($stringofparams)
	if [ true = "$Z" ] ; then echo "DEBUG! paramsarray: "${paramsarray[*]}; fi
	output='';
	#arraylength stores the number of parameters
	arraylength=${#paramsarray[*]}
	((arraylengthminusone=$arraylength-1))
	#echo "debug arraylengthminusone " $arraylengthminusone
	#this flag will track which param we are fuzzing (lets initialise it down to 0): 	
	paramflag=0
	#this sets the + and - range of numeric values
	if [ true = "$r" ] ; then 
		ranger=$rangerVal #this has already been set and can be user-controlled via the -r switch
	else
		ranger=5
	fi
	fullrange=$((ranger+ranger))
	fullrange=$((fullrange+1))
	
							
	##BEGINING OF PER-PARAMETER LOOP
	for paramstring in ${paramsarray[*]}; do
		#echo "paramstring: $paramstring"
		rm ./numlist.txt 2>/dev/null
		#work out the name and value of the current parameter:
		pval=`echo $paramstring | cut -d "=" -f2`
		pname=`echo $paramstring | cut -d "=" -f1`
		comparepage=`echo $i | cut -d " " -f 2 | cut -d "?" -f 1`

		if [ true = "$Z" ] ; then echo "DEBUG! page: "$comparepage; fi
		if [ true = "$Z" ] ; then echo "DEBUG! pname: "$pname; fi
		if [ true = "$Z" ] ; then echo "DEBUG! pval: "$pval; fi

		if [[ true != "$m" ]] ; then #normal usage, not multi-burplog parsing mode
			#does the current parameter value look like a number?:
			string=`echo "$pval" | grep -o "[0-9]*"`
			if [[ "$string" != "" ]] ; then
				if [[ "$string" == "$pval" ]] ; then
					echo "Param $pname appears to have a numeric value: $pval"
					op=0		
					while (($op<$ranger)) ; do
						op=$((op+1))
						numericparam=$((((pval+op))-$ranger))
						if (($numericparam>0)) ; then
							echo "$numericparam" >> ./numlist.txt
						fi
					done					
					op=0
					while (($op<$ranger)) ; do
						op=$((op+1))
						numericparam=$((pval+op))
						echo "$numericparam" >> ./numlist.txt
					done
				else
					echo "Param $pname does not appear to have a numeric value: $pval"
					#we skip to the end of the per-param loop (after incrementing the paramflag) to avoid scanning this parameter:
					((paramflag=$paramflag+1))
					continue
				fi
			else
				echo "Param $pname does not appear to have a numeric value: $pval"
				#we skip to the end of the per-param loop (after incrementing the paramflag) to avoid scanning this parameter:
				((paramflag=$paramflag+1))
				continue			
			fi
		else # multi burplog parsing mode is activated
			echo "Searching second burplog for parameters called $pname"
			cat $secondburplog | while read SEARCH ; do
				if [[ $SEARCH =~ $equals && !($SEARCH =~ $colon) && ($SEARCH =~ $question) && !($SEARCH =~ $equalcheck) ]]; then
					scan=`echo $SEARCH | grep -o "$pname=[^ ]*" | cut -d "=" -f2 | cut -d "&" -f1`
					if [[ $scan != "" ]] ; then
						echo "Match: $scan"
						echo "$scan" >> ./numlist.txt
					fi
				fi
			done				
		fi
		#echo "numlist:"
		if [[ "$m" == true ]] ; then
			cat ./numlist.txt 2>/dev/null | sort | uniq > ./out1.txt
			cp ./out1.txt ./numlist.txt
		fi

		#((payloadcounter=0))	
		#clean down the ./responsediffs/tmp/ dir - this is where temporary, per parameter diffs are stored:	
		rm ./responsediffs/tmp/* 2>/dev/null
		##BEGINING OF PER-PAYLOAD LOOP
		cat ./numlist.txt 2>/dev/null | while read payload; do
			#payloadcounter is not used for logic, it just presents the user with the payload number			
			payloadcounter=$((payloadcounter+1))
			if [ true = "$Z" ] ; then echo "debug payload counter: $payloadcounter" ;fi 
			# the output buffer will hold the final string of params including the injected param and the normal ones
			# lets clear it down at the begining of the loop:
			output=''
			# for each parameter in a given URL we need to create a request where one of the parameters has 
			# a payload injected but all the others are 'normal'. A normal request like this:
			# http://www.foobar.com/foo.aspx?a=1&b=2&c=3
			# ... should be fuzzed like this:
			# http://www.foobar.com/foo.aspx?a=PAYLOAD&b=2&c=3
			# http://www.foobar.com/foo.aspx?a=1&b=PAYLOAD&c=3
			# http://www.foobar.com/foo.aspx?a=1&b=2&c=PAYLOAD
			# so, we need an inner loop that will, for each parameter in the URL
			# create a request with one injected parameter.
			# we will use the paramflag variable to determine which param is to be injected.
			# y will be the innerloop iterator. where y=paramflag, we will inject our payload.
			# note that while y increments for each loop iteration, paramflag does not 
			for (( y = 0; y <= $arraylengthminusone; y += 1 )); do
				if [ true = "$Z" ] ; then echo "DEBUG! payload: "$payload;fi	
				if [ true = "$Z" ] ; then echo "DEBUG! y: $y" ; fi
				if [ true = "$Z" ] ; then echo "DEBUG! paramflag: $paramflag"; fi
				if (( $y == $paramflag )) ; then #inject the payload into this parameter:
					#(the -R path is for REST params:)
					if [[ true != "$R" ]]; then
						if [ "$multipartPOSTURL" == 1 ] ; then #mulipart form: wrap payload in double quotes
							output=$output`echo ${paramsarray[$y]} | cut -d "=" -f1`"="$payload
						else # normal request:
							output=$output`echo ${paramsarray[$y]} | cut -d "=" -f1`"="$payload
						fi
					else					
						output=$output$payload
					fi
					if [ true = "$Z" ] ; then echo "DEBUG! output after payload injection: $output";fi
					if [ true = "$Z" ] ; then echo "DEBUG! paramsarray at y: " ${paramsarray[$y]};fi
					paramtotest=`echo ${paramsarray[$y]} | cut -d "=" -f1`
					if [ true = "$Z" ] ; then echo "DEBUG! paramtotest: "$paramtotest;fi					
				else #we are not injecting this parameter, so print it out as normal:
					output=$output${paramsarray[$y]}
				fi
				#this line works out if we need to append an & to the parameter value:
				if [[ true != "$R" ]]; then
					if (($y == $arraylengthminusone)) ; then 
						foobar="foobar"
						#no need to add a '&' suffix to $output as no more params left to add...
					else 
						output=$output"&"
					fi 
				else	
					if (($y == $arraylengthminusone)) ; then 
						foobar="foobar"
						#no need to add a '&' suffix to $output as no more params left to add...
					else 
						output=$output"/"
					fi 
				fi
				#if we are testing the last parameter, we have a full list of params ready to go to the scanner:				
				if (($y == $arraylengthminusone))
					###IMPORTANT: this instruction MUST BE HERE!!!:
					then asd=1
					
					#create two requests - one clean, one evil
					if [[ true != "$R" ]]; then
						
						r=$uhostname$page"?"$output
						i=$uhostname$page"?"$params
						#echo "r:" $r
						#echo "i:" $i

					else
						r=$uhostname"/"$output
						i=$uhostname"/"$params
					fi
					if [ true = "$Z" ] ; then echo "Output: $output";fi
					# beginning of request section

					#this calls the mainrequester function
					mainrequester
					
					#beginning of response parsing section
                                        if [ true = "$Z" ] ; then echo "DEBUG! Entering response analysis phase";fi 
					#check the response code and alert the user if its not 200:					
					reponseStatusCode=`echo $and1eq2 | cut -d ":" -f 1`;
					if [[ "$reponseStatusCode" != "200" && "$reponseStatusCode" != "404" ]]
						then echo "ALERT: Status code "$reponseStatusCode" response";
					fi 
					#beginning of response diffing section
					
					#this was great but didnt work for large pages :-(
					#mydiff=`grep -f ./dump ./dumpfile -v`
					

					mydiff=`diff ./dump ./dumpfile`
					#echo "payload $payload"
					#echo "pval $pval"

					if [[ $mydiff != "" && "$payload" != "$pval" ]] ; then
						#this line writes out the difference between the responses from the 'clean' and 'evil' requests: 
						diff ./dump ./dumpfile > ./responsediffs/tmp/$safefilename-resdiff-$K-$payloadcounter-$reqcount.txt
 
						if [[ "$m" == true ]] ; then
							shortdiff=`echo $mydiff | head -n 1`
							#this line writes out the difference between the responses from the 'clean' and 'evil' requests: 
							echo $mydiff > ./responsediffs/$safefilename-resdiff-$K-$payloadcounter-$reqcount.txt
							if [[ $method != "POST" ]]; then #we're doing a get - simples 
								echo "[DIFF: $shortdiff REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt
								echo -e '\E[31;48m'"\033[1m[DIFF: $shortdiff REQ:$K]\033[0m $method URL: $uhostname$page"?"$output" ;
								tput sgr0 # Reset attributes.
							else
								if (($firstPOSTURIURL>0)) ; then
									if [ $firstPOSTURIURL == 1 ] ; then
										echo "[DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt ] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safelogname$safefilename.txt
										echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"?"$static"??"$output";
										tput sgr0 # Reset attributes.
									else
										echo "[DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"??"$output" >> ./output/$safelogname$safefilename.txt
										echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"??"$output";
										tput sgr0 # Reset attributes.
									fi
								elif [ "$multipartPOSTURL" == 1 ] ; then
									#multipart post
									echo "[DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"???"$output" >> ./output/$safelogname$safefilename.txt
									echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"???"$output"
									tput sgr0 # Reset attributes.
								else
									#normal post
									echo "[DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt
									echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"?"$output"
									tput sgr0 # Reset attributes.
								fi
							fi
						fi
					fi		
					((reqcount=$reqcount+1))
				fi						
			done
		##END OF PER-PAYLOAD LOOP:
		done
		if [[ true != "$m" ]]; then	
			myone=`ls ./responsediffs/tmp/`
			mytwo=`ls ./responsediffs/tmp/ | head -n1`
			for i in $myone ; do 
				comp=`cmp ./responsediffs/tmp/$i ./responsediffs/tmp/$mytwo`
				if [[ $comp != "" ]] ; then
					mydiff=`diff ./responsediffs/tmp/$i ./responsediffs/tmp/$mytwo`
										
					((payloadnumber=`echo $i | cut -d "-" -f 10`))
					fpayload=`head -n "$payloadnumber" ./numlist.txt | tail -n1`
					
					oldstring=`echo $pname=$pval`
					newstring=`echo $pname=$fpayload`
					output=`echo $params | replace $oldstring $newstring`
										
					shortdiff=`echo $mydiff | head -n 1 | egrep  -o  "^*.*\-.\-."`
					#this line writes out the difference between the responses from the 'clean' and 'evil' requests: 
					echo $mydiff > ./responsediffs/$safefilename-resdiff-$K-$payloadcounter-$reqcount.txt
					if [[ $method != "POST" ]]; then #we're doing a get - simples 
						echo "[DIFF: $shortdiff REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt
						echo -e '\E[31;48m'"\033[1m[DIFF: $shortdiff REQ:$K]\033[0m $method URL: $uhostname$page"?"$output" ;
						tput sgr0 # Reset attributes.
					else
						if (($firstPOSTURIURL>0)) ; then
							if [ $firstPOSTURIURL == 1 ] ; then
								echo "[DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt ] $method URL: $uhostname$page"?"$static"??"$output" >> ./output/$safelogname$safefilename.txt
								echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"?"$static"??"$output";
								tput sgr0 # Reset attributes.
							else
								echo "[DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"??"$output" >> ./output/$safelogname$safefilename.txt
								echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"??"$output";
								tput sgr0 # Reset attributes.
							fi
						elif [ "$multipartPOSTURL" == 1 ] ; then
							#multipart post
							echo "[DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"???"$output" >> ./output/$safelogname$safefilename.txt
							echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"???"$output"
							tput sgr0 # Reset attributes.
						else
							#normal post
							echo "[DIFF: $answer REQ:$K $safefilename-resdiff-$K-$payloadcounter-$reqcount.txt] $method URL: $uhostname$page"?"$output" >> ./output/$safelogname$safefilename.txt
							echo -e '\E[31;48m'"\033[1m[LENGTH-DIFF: $answer REQ:$K]\033[0m $method URL: $uhostname$page"?"$output"
							tput sgr0 # Reset attributes.
						fi
					fi
				fi
			done
		fi
	##END OF PER-PARAMETER LOOP:
	((paramflag=$paramflag+1))
	done
##END OF PER-URL LOOP:

#this code resets the firstposturl flag which is used to handle POSTs with URLs
if [ $firstPOSTURIURL == 2 ] ; then
	firstPOSTURIURL=0
fi

#write the URL number into the session file:
echo $((K+1)) > ./session/$safelogname.$safehostname.session.txt

###this code block does aggregate reporting during the scan
rm ./aggoutputlog.txt 2>/dev/null
if [[ "$includereports" == "1" ]]; then # aggregate all prior reports:
	cat ./output/$safelogname$safehostname* > ./aggoutputlog.txt 2>/dev/null
else # just aggregate this report file only
	cat ./output/$safelogname$safefilename* > ./aggoutputlog.txt 2>/dev/null
fi

cat '' > ./alertmessage.txt 2>/dev/null
if [[ "$includereports" == "1" ]] ; then # aggregate all prior reports:
	alertmessage=`cat ./output/$safelogname$safehostname* 2>/dev/null | cut -d " " -f1,2 | cut -d "[" -f2 | sort -r | uniq`
else # just aggregate this report file only
	alertmessage=`cat ./output/$safelogname$safefilename* 2>/dev/null | cut -d " " -f1,2 | cut -d "[" -f2 | sort -r | uniq`
fi

echo "$alertmessage" > ./alertmessage.txt 2>/dev/null

if [[ $alertmessage != "" ]] ; then
	echo "Update: Aggregated list of vulnerability types found:"
		cat ./alertmessage.txt | while read iter ; do 
		foo=`grep -c "$iter" ./aggoutputlog.txt` 
		echo $iter "("$foo")" 
	done
fi

done

#fi
# that 'fi' above is the end of the scan loop

#if you get here, youve finished scanning so write nothing into the session file to clear it down:
echo "" > ./session/$safehostname.session.txt

#need to do this at the end to clean up:
#need to update this

rm ./parameters_to_skip.txt 2>/dev/null
rm scannerinputlist.txt 2>/dev/null
rm cleanscannerinputlist.txt 2>/dev/null
rm 0 2>/dev/null
rm dump 2>/dev/null
rm dumpfile 2>/dev/null
rm 1scannerinputlist.txt 2>/dev/null
rm search.txt 2>/dev/null
rm dumpfile 2>/dev/null
rm dump 2>/dev/null
rm payloads.txt 2>/dev/null

# this sorts the results alphabetically in reverse to make the good stuff float to the top of the page, and the errors sink to the bottom
cat ./aggoutputlog.txt 2>/dev/null | sort -r | uniq > ./output/$safelogname-sorted-$safefilename.txt  
#cat ./output/$safelogname$safefilename.status.txt 2>/dev/null | sort | uniq >> ./output/$safelogname-sorted-$safefilename.txt

# code that parses the output .txt file and creates a nice html report:
echo "<html>" >> ./output/$safelogname-report-$safefilename.html
echo "<head>" >> ./output/$safelogname-report-$safefilename.html
echo "<title>SQLifuzzer Results Page</title>" >> ./output/$safelogname-report-$safefilename.html
echo "<body bgcolor="Silver">" >> ./output/$safelogname-report-$safefilename.html
echo "<H3>SQLifuzzer Test Results</H3>" >> ./output/$safelogname-report-$safefilename.html
echo "Output file: ./output/$safelogname-sorted-$safefilename.txt" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
echo "Host scanned: $uhostname" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
echo "Time of scan: $(date)" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
echo "<H4>Aggregate Vulnerability List</H4>" >> ./output/$safelogname-report-$safefilename.html
cat ./alertmessage.txt | while read iter ; do 
	foo=`grep -c "$iter" ./aggoutputlog.txt` 
	echo "$iter" "(""$foo"")" >> ./output/$safelogname-report-$safefilename.html
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
done
echo "<br>" >> ./output/$safelogname-report-$safefilename.html
mytest=`cat ./listofxpathelements.txt 2>/dev/null`
if [[ "$mytest" != "" ]] ; then
	echo "<H4>XPath Injection Data</H4>" >> ./output/$safelogname-report-$safefilename.html
	cat ./listofxpathelements.txt | while read bLINE ; do
		echo "$bLINE" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
	done
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
fi
echo "<H4>Detailed Results</H4>" >> ./output/$safelogname-report-$safefilename.html
echo "------------------------------------------------------------------" >> ./output/$safelogname-report-$safefilename.html
echo "<br>" >> ./output/$safelogname-report-$safefilename.html

echo "Reading in ./output/$safelogname-sorted-$safefilename.txt"
echo "Compiling report to create ./output/$safelogname-report-$safefilename.html"

cat ./output/$safelogname-sorted-$safefilename.txt | while read aLINE ; do
	echo -n "."
	message=`echo $aLINE|cut -d "]" -f1|cut -d "[" -f2`
	#echo $message
	fullrequest=`echo $aLINE|cut -d "]" -f2`
	method=`echo $fullrequest | cut -d " " -f1`
	request=`echo $fullrequest | cut -d " " -f3`

	protocol=`echo $request | cut -d "/" -f1`
	host=`echo $request | cut -d "/" -f3`
	#the below is named oddly - it is really 'page + params': /subdir/page.aspx?foo=1&bar=1
	params=`echo $request | cut -d "/" -f4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30`
	params2=`echo "$aLINE" | cut -d "?" -f4`

	#echo "params2 $params2"
	#the below is also named oddly - it is really 'subdirs + page': subdir/page.aspx
	page=`echo $params | cut -d "?" -f1`

	#echo "fullrequest: $fullrequest"
	#echo "message $message";
	#echo "method $method";
	#echo "request $request";
	#echo "protocol $protocol"
	#echo "host $host"
	#echo "params: $params"

	if [[ "$method" == "POST" ]] ; then
		if [[ $request =~ "??" && !($request =~ "???") ]] ; then #postURI POSTs only
			postdataparams=`echo $params | cut -d "?" -f4`
			postURIparams=`echo $params | cut -d "?" -f2`
		elif [[ $request =~ "???" ]] ; then #multipart POSTs only
			#echo "params2: "$params2
			postdataparams=`echo $params2 | cut -d "?" -f4`	
			#echo "postdataparams: "$postdataparams
			echo $postdataparams | tr "&" "\n" > ./postdataparams.txt # for multipart posts: need a 'while read' later as the payloads have unencoded spaces				
		else
			postdataparams=`echo $params | cut -d "?" -f2`			
			#echo "postdataparams $postdataparams"
		fi
		postdataparamslist=`echo "$postdataparams"| replace "&" " "`
	fi
	#cat ./postdataparams.txt
	echo "$message" >> ./output/$safelogname-report-$safefilename.html
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
	if [[ "$method" == "GET" ]]  ; then 
		echo "$method /$params" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html	
		echo "Host: $host" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
		echo "<a href="$request">Submit Query</a>" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
	else
		if [[ $request =~ "??" && !($request =~ "???") ]] ; then #post URI params 
			echo "$method /$page?$postURIparams" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "Host: $host" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html

			decodeinput=$postdataparams
			encodeme
			decparam=$decodeoutput

			#echo "$decparam" >> ./output/$safelogname-report-$safefilename.html
			echo "<form action="$protocol//$host/$page?$postURIparams" method="POST">" >> ./output/$safelogname-report-$safefilename.html
			for param in `echo $postdataparamslist` ; do
				paramname=`echo $param | cut -d "=" -f 1`
				paramval=`echo $param | cut -d "=" -f 2,3,4,5,6`
				#this is the in the inverse of the encoding line in the fuzz loop
				decodeinput=$paramval
				encodeme
				decparam=$decodeoutput
				echo -n "<Input type="text" size=80 name=\"$paramname\" value=\"$decparam\"> " >> ./output/$safelogname-report-$safefilename.html
			done
			echo "<input type="submit"> " >> ./output/$safelogname-report-$safefilename.html
			echo "</form> " >> ./output/$safelogname-report-$safefilename.html
		elif [[ $request =~ "???" ]] ; then #multipart post 
			echo "MULTIPART POST /$page" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "Host: $host" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html

			echo "<form action="$protocol//$host/$page" enctype="multipart/form-data" method="POST">" >> ./output/$safelogname-report-$safefilename.html
			cat ./postdataparams.txt | while read param ; do
				paramname=`echo $param | cut -d "=" -f 1`
				paramval=`echo $param | cut -d "=" -f 2,3,4,5,6`
				echo -n "<Input type="text" size=80 name=\"$paramname\" value=\"$paramval\"> " >> ./output/$safelogname-report-$safefilename.html
			done
			echo "<input type="submit"> " >> ./output/$safelogname-report-$safefilename.html
			echo "</form> " >> ./output/$safelogname-report-$safefilename.html
		else # normal post
			echo "$method /$page" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "Host: $host" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			decodeinput=$postdataparams
			encodeme
			decparam=$decodeoutput
			#echo "DEBUG! decparam: $decparam"
			#echo "$decparam" >> ./output/$safelogname-report-$safefilename.html
			#echo "$postdataparams"
			#echo "$postdataparamslist"
			echo "<form action="$protocol//$host/$page" method="POST">" >> ./output/$safelogname-report-$safefilename.html
			for param in `echo $postdataparamslist` ; do
				paramname=`echo $param | cut -d "=" -f 1`
				paramval=`echo $param | cut -d "=" -f 2,3,4,5,6`
				decodeinput=$paramval
				encodeme
				decparam=$decodeoutput
				echo -n "<Input type="text" size=80 name=\"$paramname\" value=\"$decparam\"> " >> ./output/$safelogname-report-$safefilename.html
				#echo "<br>" >> ./output/$safelogname-report-$safefilename.html
			done
			echo "<input type="submit"> " >> ./output/$safelogname-report-$safefilename.html
			echo "</form> " >> ./output/$safelogname-report-$safefilename.html
		fi
	fi
	if [[ "$message" =~ "DATA-EXTRACTED:" ]] ; then
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
		respdiff=`echo $message | grep -o $safehostname.*` 
		#echo "debug message=$message"
		#echo "debug respdiff=$respdiff"
		echo " <a href="./../responsediffs/$respdiff">View Extracted Data</a>" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html	
	fi
	if [[ "$message" =~ "LENGTH-DIFF:" ]] ; then
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html
		respdiff=`echo $message | cut -d " " -f 4`
		echo " <a href="./../responsediffs/$respdiff">View Response Diff</a>" >> ./output/$safelogname-report-$safefilename.html
		echo "<br>" >> ./output/$safelogname-report-$safefilename.html	
	fi
	echo "------------------------------------------------------------------" >> ./output/$safelogname-report-$safefilename.html
	echo "<br>" >> ./output/$safelogname-report-$safefilename.html
done

echo "" > ./session/$safelogname.$safehostname.siteanalysis.txt	
echo "</body>" >> ./output/$safelogname-report-$safefilename.html
echo "</html>" >> ./output/$safelogname-report-$safefilename.html 
echo ""
rm ./aggoutputlog.txt 2>/dev/null

cp ./alertmessage.txt ./useful.txt
rm ./alertmessage.txt 2>/dev/null
rm ./listofxpathnodes.txt 2>/dev/null
rm ./listofxpathelements.txt 2>/dev/null
rm ./multipartlist.txt 2>/dev/null
rm ./selcheck1 2>/dev/null
rm ./useful.txt 2>/dev/null
rm ./numlist.txt 2>/dev/null
rm ./params 2>/dev/null
rm ./test 2>/dev/null
rm ./diff.txt 2>/dev/null
rm ./clean.txt 2>/dev/null
rm ./out1.txt 2>/dev/null



echo "Done. HTML report written to ./output/$safelogname-report-$safefilename.html"
echo "Attempting to open ./output/$safelogname-report-$safefilename.html with firefox"
firefox ./output/$safelogname-report-$safefilename.html 2>/dev/null &
