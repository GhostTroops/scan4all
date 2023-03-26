#!/bin/bash
function doMasScan {
    if [[ -f $1 ]] ; then
        echo $PPSSWWDD| sudo -S ksubdomain enum -b 5M --dl $1  -f $HOME/MyWork/scan4all/config/database/subdomain.txt -o $HOME/MyWork/scan4all/atckData/$1_ksubdomain.txt
    else
        echo $PPSSWWDD| sudo -S ksubdomain enum -b 5M -d $1  -f $HOME/MyWork/scan4all/config/database/subdomain.txt -o $HOME/MyWork/scan4all/atckData/$1_ksubdomain.txt
    fi
}
doMasScan $1


