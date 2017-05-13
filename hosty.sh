#!/bin/bash

# Add ad-blocking hosts files in this array
HOSTS=(
    "http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz" #p2p
    "http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz"
    "http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz"
    "http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz" #spyware
    "http://list.iblocklist.com/?list=dgxtneitpuvgqqcpfulq&fileformat=p2p&archiveformat=gz" #ads
    "http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz" #badpeers
    "http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz" #webexploit
    "http://list.iblocklist.com/?list=npkuuhuxcsllnhoamkvm&fileformat=p2p&archiveformat=gz" #malicious
    "http://list.iblocklist.com/?list=mcvxsnihddgutbjfbghy&fileformat=p2p&archiveformat=gz" #spider
    "http://list.iblocklist.com/?list=zbdlwrqkabxbcppvrnos&fileformat=p2p&archiveformat=gz" #drop-zombie
    "https://www.malwaredomainlist.com/hostslist/hosts.txt" #malware
    "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt" #blocktracker
    "https://fanboy.co.nz/fanboy-antifacebook.txt" #fb-track
    "http://malwareurls.joxeankoret.com/normal.txt" #malware
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/SpotifyAds/hosts" #spotify-ads
    "http://www.squirrelconspiracy.net/abp/facebook-privacy-list.txt" #fb-privacy
    "http://list.iblocklist.com/lists/atma/atma" #atma
    "http://list.iblocklist.com/lists/dchubad/hacker" #hacker
    "http://list.iblocklist.com/lists/tbg/bogon" #bogon
    "http://list.iblocklist.com/?list=cdmdbprvldivlqsaqjol&fileformat=p2p&archiveformat=gz" #verizon
    "http://list.iblocklist.com/?list=grbtkzijgrowvobvessf&fileformat=p2p&archiveformat=gz" #at&t
    "http://list.iblocklist.com/?list=czvaehmjpsnwwttrdoyl&fileformat=p2p&archiveformat=gz" #scanning for vulnerabilities and DDOS attacks
    "https://easylist-downloads.adblockplus.org/fb_annoyances_newsfeed.txt" #fb-ads-newsfeed
    "https://raw.githubusercontent.com/eladkarako/hosts.eladkarako.com/master/build/hosts_adblock.txt")

     
# Add AdBlock Plus rules files in this array
RULES=("http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz" #p2p
    "http://list.iblocklist.com/?list=gyisgnzbhppbvsphucsw&fileformat=p2p&archiveformat=gz"
    "http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz"
    "http://list.iblocklist.com/?list=llvtlsjyoyiczbkjsxpf&fileformat=p2p&archiveformat=gz" #spyware
    "http://list.iblocklist.com/?list=dgxtneitpuvgqqcpfulq&fileformat=p2p&archiveformat=gz" #ads
    "http://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=p2p&archiveformat=gz" #badpeers
    "http://list.iblocklist.com/?list=ghlzqtqxnzctvvajwwag&fileformat=p2p&archiveformat=gz" #webexploit
    "http://list.iblocklist.com/?list=npkuuhuxcsllnhoamkvm&fileformat=p2p&archiveformat=gz" #malicious
    "http://list.iblocklist.com/?list=mcvxsnihddgutbjfbghy&fileformat=p2p&archiveformat=gz" #spider
    "http://list.iblocklist.com/?list=zbdlwrqkabxbcppvrnos&fileformat=p2p&archiveformat=gz" #drop-zombie
    "https://www.malwaredomainlist.com/hostslist/hosts.txt" #malware
    "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt" #blocktracker
    "https://fanboy.co.nz/fanboy-antifacebook.txt" #fb-track
    "http://malwareurls.joxeankoret.com/normal.txt" #malware
    "https://raw.githubusercontent.com/FadeMind/hosts.extras/master/SpotifyAds/hosts" #spotify-ads
    "http://www.squirrelconspiracy.net/abp/facebook-privacy-list.txt" #fb-privacy
    "http://list.iblocklist.com/lists/atma/atma" #atma
    "http://list.iblocklist.com/lists/dchubad/hacker" #hacker
    "http://list.iblocklist.com/lists/tbg/bogon" #bogon
    "http://list.iblocklist.com/?list=cdmdbprvldivlqsaqjol&fileformat=p2p&archiveformat=gz" #verizon
    "http://list.iblocklist.com/?list=grbtkzijgrowvobvessf&fileformat=p2p&archiveformat=gz" #at&t
    "http://list.iblocklist.com/?list=czvaehmjpsnwwttrdoyl&fileformat=p2p&archiveformat=gz" #scanning for vulnerabilities and DDOS attacks
    "https://easylist-downloads.adblockplus.org/fb_annoyances_newsfeed.txt" #fb-ads-newsfeed
    "https://raw.githubusercontent.com/eladkarako/hosts.eladkarako.com/master/build/hosts_adblock.txt")
# Set IP to redirect
IP="0.0.0.0"

if [ -f ~/.hosty ]; then
    while read -r line
    do
        HOSTS+=("$line")
    done < ~/.hosty
fi

gnused() {
    if hash gsed 2>/dev/null; then
        gsed "$@"
    else
        sed "$@"
    fi
}

dwn() {
    wget --no-cache -nv -O $aux $1
    if [ $? != 0 ]; then
        return $?
    fi
    if [[ $1 == *.zip ]]; then
        zcat "$aux" > "$tmp"
        cat "$tmp" > "$aux"
        if [ $? != 0 ]; then
            return $?
        fi
    elif [[ $1 == *.7z ]]; then
        7z e -so -bd "$aux" 2>/dev/null > $1
        if [ $? != 0 ]; then
            return $?
        fi
    fi
    return 0
}

orig=$(mktemp)
ln=$(gnused -n '/^# Ad blocking hosts generated/=' /etc/hosts)
if [ -z $ln ]; then
    if [ "$1" == "--restore" ]; then
        echo "There is nothing to restore."
        exit 0
    fi
    cat /etc/hosts > $orig
else
    let ln-=1
    head -n $ln /etc/hosts > $orig
    if [ "$1" == "--restore" ]; then
        sudo bash -c "cat $orig > /etc/hosts"
        echo "/etc/hosts restore completed."
        exit 0
    fi
fi

# If this is our first run, create a whitelist file and set to read-only for safety
if [ ! -f /etc/hosts.whitelist ]
then
    echo "Creating whitelist file..."
    sudo touch /etc/hosts.whitelist
    sudo chmod 444 /etc/hosts.whitelist
    echo
fi
if [ ! -f /etc/hosts.blacklist ]
then
    echo "Creating blacklist file..."
    sudo touch /etc/hosts.blacklist
    sudo chmod 444 /etc/hosts.blacklist
    echo
fi

host=$(mktemp)
aux=$(mktemp)
tmp=$(mktemp)
white=$(mktemp)

echo "Downloading ad-blocking files..."
# Obtain various hosts files and merge into one
for i in "${HOSTS[@]}"
do
    dwn $i
    if [ $? != 0 ]; then
        echo "Error downloading $i"
    else
        gnused -e '/^[[:space:]]*\(127\.0\.0\.1\|0\.0\.0\.0\|255\.255\.255\.0\)[[:space:]]/!d' -e 's/[[:space:]]\+/ /g' $aux | awk '$2~/^[^# ]/ {print $2}' >> $host
    fi
done
# Obtain various AdBlock Plus rules files and merge into one
for i in "${RULES[@]}"
do
    dwn $i
    if [ $? != 0 ]; then
        echo "Error downloading $i"
    else
        awk '/^\|\|[a-z][a-z0-9\-_.]+\.[a-z]+\^$/ {substr($0,3,length($0)-3)}' $aux >> $host
    fi
done


echo
echo "Excluding localhost and similar domains..."
gnused -e '/^\(localhost\|localhost\.localdomain\|local\|broadcasthost\|ip6-localhost\|ip6-loopback\|ip6-localnet\|ip6-mcastprefix\|ip6-allnodes\|ip6-allrouters\)$/d' -i $host

if [ "$1" != "--all" ] && [ "$2" != "--all" ]; then
    echo
    echo "Applying recommended whitelist (Run hosty --all to avoid this step)..."
    gnused -e '/\(smarturl\.it\|da\.feedsportal\.com\|any\.gs\|pixel\.everesttech\.net\|www\.googleadservices\.com\|maxcdn\.com\|static\.addtoany\.com\|addthis\.com\|googletagmanager\.com\|addthiscdn\.com\|sharethis\.com\|twitter\.com\|pinterest\.com\|ojrq\.net\|rpxnow\.com\|google-analytics\.com\|shorte\.st\|adf\.ly\|www\.linkbucks\.com\|static\.linkbucks\.com\)$/d' -i $host
fi

echo
echo "Applying user blacklist..."
cat "/etc/hosts.blacklist" >> $host
if [ -f ~/.hosty.blacklist ]; then
    cat "~/.hosty.blacklist" >> $host
fi

echo
echo "Applying user whitelist, cleaning and de-duplicating..."
cat /etc/hosts.whitelist > $white
if [ -f ~/.hosty.whitelist ]; then
    cat "~/.hosty.whitelist" >> $white
fi

awk '/^\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {print $2}' $orig >> $white
awk -v ip=$IP 'FNR==NR {arr[$1]++} FNR!=NR {if (!arr[$1]++) print ip, $1}' $white $host > $aux

echo
echo "Building /etc/hosts..."
cat $orig > $host

echo "# Ad blocking hosts generated $(date)" >> $host
echo "# Don't write below this line. It will be lost if you run hosty again." >> $host
cat $aux >> $host

ln=$(grep -c "$IP" $host)

if [ "$1" != "--debug" ] && [ "$2" != "--debug" ]; then
    sudo bash -c "cat $host > /etc/hosts"
else
    echo
    echo "You can see the results in $host"
fi

echo
echo "Done, $ln websites blocked."
echo
echo "You can always restore your original hosts file with this command:"
echo "  $ sudo hosty --restore"
