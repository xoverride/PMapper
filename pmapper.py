#!/usr/bin/env python

"""
Wrap around principalmapper/__main__.py
"""


#  Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.
#
#      Principal Mapper is free software: you can redistribute it and/or modify
#      it under the terms of the GNU Affero General Public License as published by
#      the Free Software Foundation, either version 3 of the License, or
#      (at your option) any later version.
#
#      Principal Mapper is distributed in the hope that it will be useful,
#      but WITHOUT ANY WARRANTY; without even the implied warranty of
#      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#      GNU Affero General Public License for more details.
#
#      You should have received a copy of the GNU Affero General Public License
#      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.

import sys

from principalmapper.__main__ import main

import time

if __name__ == '__main__':
    start_time = time.time()  # Capture the start time

    result = main()
    
    end_time = time.time()  # Capture the end time
    total_time = end_time - start_time  # Calculate total time taken

    print(f"Start Time: {time.ctime(start_time)}")
    print(f"End Time: {time.ctime(end_time)}")
    print(f"Total Time Taken: {total_time} seconds")
    sys.exit(result)
