# H2o
h2o is useful ida plugin. h2o give you some advance manipulation that ida wasnt support.
now there is 3 option:

1. AdvanveGo (Shift+G)

2. AdvanceSearch (Shift+S)

3. Rva extractor (Shift+R)

AdvanceSearch is very useful when you dealing with constructor or big initialization function.

![alt tag](https://github.com/shmuelyr/H2o/blob/master/image/SearchEx.png)

with GoEx you can go to any rva without calculate it, just write base+rva
its very useful when you debug code and your debugger load dll/your image with ASLR mode.

![alt tag](https://github.com/shmuelyr/H2o/blob/master/image/GoEx.png)

to finish this one Shift+R return RVA for selected address

![alt tag](https://github.com/shmuelyr/H2o/blob/master/image/Rva.png)

for example:

![alt tag](https://github.com/shmuelyr/H2o/blob/master/image/RgxSearchEx.png)

![alt tag](https://github.com/shmuelyr/H2o/blob/master/image/SearchResult.png)

Happy reverseing!
