set terminal svg
set datafile separator ','

set output 'network_delay_[h=0.51].svg'
# set yrange [0:1]
plot 'data/network_delay_[h=0.51,d=0.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.01].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.02].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.03].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.04].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.05].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.06].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.07].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.08].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.09].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.51,d=0.10].csv' using 1:(log(1-$2)) with lines, \

set output 'network_delay_[h=0.55].svg'
# set yrange [0:1]
plot 'data/network_delay_[h=0.55,d=0.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.05].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.10].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.15].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.20].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.25].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.30].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.35].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.40].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.45].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.55,d=0.50].csv' using 1:(log(1-$2)) with lines, \

set output 'network_delay_[h=0.67].svg'
# set yrange [0:1]
plot 'data/network_delay_[h=0.67,d=0.20].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=0.40].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=0.80].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=1.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=1.20].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=1.40].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=1.60].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=1.80].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=2.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=2.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.67,d=2.00].csv' using 1:(log(1-$2)) with lines, \

set output 'network_delay_[h=0.90].svg'
# set yrange [0:1]
plot 'data/network_delay_[h=0.90,d=0.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=1.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=2.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=3.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=4.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=5.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=6.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=7.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=8.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=9.00].csv' using 1:(log(1-$2)) with lines, \
     'data/network_delay_[h=0.90,d=10.00].csv' using 1:(log(1-$2)) with lines, \

set title
set xlabel
set ylabel
set xrange [*:*]
set yrange [*:*]

set output 'prove.svg'
set logscale xy 2
plot 'data/prove.csv' with lines

set output 'verify.svg'
set logscale xy 2
plot 'data/verify.csv' with lines

set output 'agg_verify.svg'
unset logscale xy
plot 'data/agg_verify.csv' using 1:($2/1000) with lines
