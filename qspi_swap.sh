current_dir=$PWD
current_dir="$(basename $current_dir)"

while read filename
do
	board_name=${filename%%/*}
	filename=${filename#*/}

	if [ "$board_name" = "$current_dir" ]; then
		if [ -e $filename ]; then
			swapped_file="$filename.swapped"
			if [ -e "byte_swap.tcl" ]; then
				tclsh ./byte_swap.tcl $filename $swapped_file 8
			else
				tclsh ../tools/byte_swap.tcl $filename $swapped_file 8
			fi
		fi
	fi
done < $1
