rm ~/junk/tor.7z
7z a ~/junk/tor.7z -xr'!.git/' -xr'!b/' -xr'!build/' -xr'!testdata' $*
