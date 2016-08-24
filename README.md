# hack400tool - security handling tools for IBM Power Systems (formerly known as AS/400)
# Copyright (C) 2010-2016  Bart Kulach

"hack400tool" is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

"hack400tool" is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

------------------------------------------------------------------------------------------
For executables, see "dist" folder.

2016-08-24 Updates

Main changes:
- temporary results are stored in sqlite database (better performance and stability)
- support for SHA1 hash extraction for John the Ripper at ibmiscanner (see www.hackthelegacy.org for details)
- other added options for ibmiscanner 
- minor GUI improvements (threading, progress bar)