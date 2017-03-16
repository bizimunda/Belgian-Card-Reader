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

using System;
using System.Collections.Generic;

using System.Text;

using System.Runtime.InteropServices;

using Net.Sf.Pkcs11;
using Net.Sf.Pkcs11.Objects;
using Net.Sf.Pkcs11.Wrapper;

using System.Security.Cryptography.X509Certificates;

namespace EidSamples
{
    class HamidReadData
    {
        public string surName, lastName, dob, nationality, gender, streetAndNumber, postCode, municipality, nationalNumber;
        private Module m = null;
        private String mFileName;
        /// <summary>
        /// Default constructor. Will instantiate the beidpkcs11.dll pkcs11 module
        /// </summary>
        public HamidReadData()
        {
            mFileName = "beidpkcs11.dll";
        }
        public HamidReadData(String moduleFileName)
        {
            mFileName = moduleFileName;
        }
        /// <summary>
        /// Gets the description of the first slot (cardreader) found
        /// </summary>
        /// <returns>Description of the first slot found</returns>

        public void GetAllData()
        {
            String label = "";
            String value = "";
            byte[] file;
            if (m == null)
            {
                m = Module.GetInstance(mFileName);
            }
            try
            {
                Slot[] slotlist = m.GetSlotList(true);
                if (slotlist.Length > 0)
                {
                    Slot slot = slotlist[0];
                    Session session = slot.Token.OpenSession(true);
                    ByteArrayAttribute classAttribute = new ByteArrayAttribute(CKA.CLASS);
                    classAttribute.Value = BitConverter.GetBytes((uint)Net.Sf.Pkcs11.Wrapper.CKO.DATA);
                    ByteArrayAttribute labelAttribute = new ByteArrayAttribute(CKA.LABEL);
                    session.FindObjectsInit(new P11Attribute[] { classAttribute });
                    P11Object[] foundObjects = session.FindObjects(50);
                    Data data;
                    for (int i = 17; i < foundObjects.Length; i++)
                    {
                        data = foundObjects[i] as Data;
                        label = data.Label.ToString();
                        if (label == null)
                        {
                            label = "";
                        }
                        value = "";
                        switch (label)
                        {
                            case "[CharArrayAttribute Value=surname]":
                                if (data.Value.Value != null)
                                {
                                    value = System.Text.Encoding.UTF8.GetString(data.Value.Value);
                                    surName = value;
                                }
                                break;
                            case "[CharArrayAttribute Value=firstnames]":
                                if (data.Value.Value != null)
                                {
                                    value = System.Text.Encoding.UTF8.GetString(data.Value.Value);
                                    lastName = value;
                                }
                                break;
                            case "[CharArrayAttribute Value=nationality]":
                                if (data.Value.Value != null)
                                {
                                    value = System.Text.Encoding.UTF8.GetString(data.Value.Value);
                                    nationality = value;
                                }
                                break;
                            case "[CharArrayAttribute Value=national_number]":
                                if (data.Value.Value != null)
                                {
                                    value = System.Text.Encoding.UTF8.GetString(data.Value.Value);
                                    nationalNumber = value;
                                }
                                break;
                            case "[CharArrayAttribute Value=date_of_birth]":
                                if (data.Value.Value != null)
                                {
                                    value = System.Text.Encoding.UTF8.GetString(data.Value.Value);
                                    dob = value;
                                }
                                break;
                            case "[CharArrayAttribute Value=gender]":
                                if (data.Value.Value != null)
                                {
                                    value = System.Text.Encoding.UTF8.GetString(data.Value.Value);
                                    gender = value;
                                }
                                break;
                            case "[CharArrayAttribute Value=address_street_and_number]":
                                if (data.Value.Value != null)
                                {
                                    value = System.Text.Encoding.UTF8.GetString(data.Value.Value);
                                    streetAndNumber = value;
                                }
                                break;
                            case "[CharArrayAttribute Value=address_zip]":
                                if (data.Value.Value != null)
                                {
                                    value = System.Text.Encoding.UTF8.GetString(data.Value.Value);
                                    postCode = value;
                                }
                                break;
                            case "[CharArrayAttribute Value=address_municipality]":
                                if (data.Value.Value != null)
                                {
                                    value = System.Text.Encoding.UTF8.GetString(data.Value.Value);
                                    municipality = value;
                                }
                                break;

                            default:
                                break;
                        }
                        //Console.WriteLine(i + " -> " + label + " : " + value);
                    }
                    session.FindObjectsFinal();
                }
                else
                {
                    Console.WriteLine("No card found\n");
                }
            }
            finally
            {
                m.Dispose();
            }
        }
    }
}
