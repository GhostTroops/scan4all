cat $1 >> $HOME/MyWork/scan4all/brute/filedic.txt
sort -u $HOME/MyWork/scan4all/brute/filedic.txt >x.txt
mv x.txt $HOME/MyWork/scan4all/brute/filedic.txt

