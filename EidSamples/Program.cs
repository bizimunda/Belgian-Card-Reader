/* ****************************************************************************

 * eID Middleware Project.
 * Copyright (C) 2010-2010 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see
 * http://www.gnu.org/licenses/.

**************************************************************************** */
using System.Collections.Generic;
using System;
using System.Security.Cryptography.X509Certificates;
using EidSamples.tests;
using System.Text;
using System.IO;

namespace EidSamples
{
    class Program
    {
        static void Main(string[] args)
        {
            
            ReadData readData = new ReadData();
            HamidReadData hamidReadData = new HamidReadData();
            hamidReadData.GetAllData();
            string surName = hamidReadData.surName;
            string lastName = hamidReadData.lastName;
            string dob = hamidReadData.dob;
            string nationality = hamidReadData.nationality;
            string gender = hamidReadData.gender;
            string streetAndNumber = hamidReadData.streetAndNumber;
            string postCode = hamidReadData.postCode;
            string municipality = hamidReadData.municipality;
            string nationalNumber = hamidReadData.nationalNumber;


            Console.WriteLine(surName);
            Console.WriteLine(lastName);
            Console.WriteLine(nationalNumber);
            Console.WriteLine(dob);
            Console.WriteLine(nationality);
            Console.WriteLine(gender);
            Console.WriteLine(streetAndNumber);
            Console.WriteLine(postCode);
            Console.WriteLine(municipality);

            Console.ReadKey();
        }

    }
} 
