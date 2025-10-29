#cat ac-logger.log | grep username | awk '{print $1, $4}' | sort -u
cat ac-logger.log | grep username | awk '{print $1, $4}'

