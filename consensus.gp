set terminal svg
set datafile separator ','

set output 'network_delay_[h=0.51].svg'
set yrange [0:1]
plot 'data/network_delay_[h=0.51,d=0.00].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.01].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.02].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.03].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.04].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.05].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.06].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.07].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.08].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.09].csv' with lines, \
     'data/network_delay_[h=0.51,d=0.10].csv' with lines, \

set output 'network_delay_[h=0.55].svg'
set yrange [0:1]
plot 'data/network_delay_[h=0.55,d=0.00].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.05].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.10].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.15].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.20].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.25].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.30].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.35].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.40].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.45].csv' with lines, \
     'data/network_delay_[h=0.55,d=0.50].csv' with lines, \

set output 'network_delay_[h=0.67].svg'
set yrange [0:1]
plot 'data/network_delay_[h=0.67,d=0.20].csv' with lines, \
     'data/network_delay_[h=0.67,d=0.40].csv' with lines, \
     'data/network_delay_[h=0.67,d=0.80].csv' with lines, \
     'data/network_delay_[h=0.67,d=1.00].csv' with lines, \
     'data/network_delay_[h=0.67,d=1.20].csv' with lines, \
     'data/network_delay_[h=0.67,d=1.40].csv' with lines, \
     'data/network_delay_[h=0.67,d=1.60].csv' with lines, \
     'data/network_delay_[h=0.67,d=1.80].csv' with lines, \
     'data/network_delay_[h=0.67,d=2.00].csv' with lines, \
     'data/network_delay_[h=0.67,d=2.00].csv' with lines, \
     'data/network_delay_[h=0.67,d=2.00].csv' with lines, \

set output 'network_delay_[h=0.90].svg'
set yrange [0:1]
plot 'data/network_delay_[h=0.90,d=0.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=1.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=2.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=3.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=4.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=5.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=6.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=7.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=8.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=9.00].csv' with lines, \
     'data/network_delay_[h=0.90,d=10.00].csv' with lines, \

set logscale y 10

set output 'bootstrap_[c=0.999].svg'
set yrange [10:5000]
plot 'data/bootstrap_[c=0.999,d=0.0].csv' with lines, \
     'data/bootstrap_[c=0.999,d=0.1].csv' with lines, \
     'data/bootstrap_[c=0.999,d=0.2].csv' with lines, \
     'data/bootstrap_[c=0.999,d=0.3].csv' with lines, \
     'data/bootstrap_[c=0.999,d=0.4].csv' with lines, \

set output 'bootstrap_[h=0.55,c=x].svg'
set yrange [10:5000]
set xrange [0.8:*]
plot 'data/bootstrap_[h=0.55,d=0.0].csv' with lines, \
     'data/bootstrap_[h=0.55,d=0.1].csv' with lines, \
     'data/bootstrap_[h=0.55,d=0.2].csv' with lines, \
     'data/bootstrap_[h=0.55,d=0.3].csv' with lines, \

set xrange [*:*]

set output 'bootstrap_[c=0.999,b=x].svg'
set yrange [10:40000]
plot 'data/bootstrap_[h=0.55,c=0.999].csv' with lines, \
     'data/bootstrap_[h=0.67,c=0.999].csv' with lines, \
     'data/bootstrap_[h=0.90,c=0.999].csv' with lines, \
     'data/bootstrap_[h=0.55,c=0.990].csv' with lines, \
     'data/bootstrap_[h=0.67,c=0.990].csv' with lines, \
     'data/bootstrap_[h=0.90,c=0.990].csv' with lines, \

