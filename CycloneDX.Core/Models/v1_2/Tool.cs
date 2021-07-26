// This file is part of CycloneDX Library for .NET
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OWASP Foundation. All Rights Reserved.

using System.Collections.Generic;
using System.Xml.Serialization;

namespace CycloneDX.Models.v1_2
{
    public class Tool
    {
        [XmlElement("vendor")]
        public string Vendor { get; set; }
        [XmlElement("name")]
        public string Name { get; set; }
        [XmlElement("version")]
        public string Version { get; set; }
        [XmlArray("hashes")]
        public List<Hash> Hashes { get; set; }

        public Tool() {}

        public Tool(v1_3.Tool tool)
        {
            Vendor = tool.Vendor;
            Name = tool.Name;
            Version = tool.Version;
            if (tool.Hashes != null)
            {
                Hashes = new List<Hash>();
                foreach (var hash in tool.Hashes)
                {
                    Hashes.Add(new Hash(hash));
                }
            }
        }
    }
}