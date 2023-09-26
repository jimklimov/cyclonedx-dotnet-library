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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Text.Json.Serialization;
using System.Xml;
using System.Xml.Serialization;
using ProtoBuf;

namespace CycloneDX.Models
{
    [SuppressMessage("Microsoft.Performance", "CA1822:MarkMembersAsStatic")]
    [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
    [XmlRoot("bom", IsNullable=false)]
    [ProtoContract]
    public class Bom : BomEntity
    {
        [XmlIgnore]
        public string BomFormat => "CycloneDX";

        private SpecificationVersion _specVersion = SpecificationVersionHelpers.CurrentVersion;
        [XmlIgnore]
        [JsonIgnore]
        public SpecificationVersion SpecVersion
        {
            get => _specVersion;
            set
            {
                _specVersion = value;
                // this is horrible, but I can't get the XML serializer to cooperate with me otherwise
                BomUtils.EnumerateAllToolChoices(this, (toolChoice) =>
                {
                    toolChoice.SpecVersion = _specVersion;
                });
                BomUtils.EnumerateAllServices(this, (service) =>
                {
                    service.SpecVersion = _specVersion;
                });
            }
        }

        // For JSON we could use a custom converter
        // but this works nicely for protobuf too
        [XmlIgnore]
        [ProtoMember(1)]
        [JsonPropertyName("specVersion")]
        public string SpecVersionString
        {
            get => SpecificationVersionHelpers.VersionString(SpecVersion);
            set
            {
                switch (value)
                {
                    case "1.0":
                        SpecVersion = SpecificationVersion.v1_0;
                        break;
                    case "1.1":
                        SpecVersion = SpecificationVersion.v1_1;
                        break;
                    case "1.2":
                        SpecVersion = SpecificationVersion.v1_2;
                        break;
                    case "1.3":
                        SpecVersion = SpecificationVersion.v1_3;
                        break;
                    case "1.4":
                        SpecVersion = SpecificationVersion.v1_4;
                        break;
                    case "1.5":
                        SpecVersion = SpecificationVersion.v1_5;
                        break;
                    default:
                        throw new ArgumentException($"Unsupported specification version: {value}");
                }
            }
        }

        [XmlAttribute("serialNumber")]
        [ProtoMember(3)]
        public string SerialNumber { get; set; }

        [XmlIgnore]
        [ProtoMember(2)]
        public int? Version { get; set; }
        [XmlAttribute("version")]
        [JsonIgnore]
        public int NonNullableVersion
        {
            get
            {
                return Version.Value;
            }
            set
            {
                Version = value;
            }
        }
        public bool ShouldSerializeNonNullableVersion() { return Version.HasValue; }

        [XmlElement("metadata")]
        [ProtoMember(4)]
        public Metadata Metadata { get; set; }

        [XmlArray("components")]
        [XmlArrayItem("component")]
        [ProtoMember(5)]
        public List<Component> Components { get; set; }

        [XmlArray("services")]
        [XmlArrayItem("service")]
        [ProtoMember(6)]
        public List<Service> Services { get; set; }
        public bool ShouldSerializeServices() { return Services?.Count > 0; }

        [XmlArray("externalReferences")]
        [XmlArrayItem("reference")]
        [ProtoMember(7)]
        public List<ExternalReference> ExternalReferences { get; set; }
        public bool ShouldSerializeExternalReferences() { return ExternalReferences?.Count > 0; }

        [XmlArray("dependencies")]
        [XmlArrayItem("dependency")]
        [ProtoMember(8)]
        public List<Dependency> Dependencies { get; set; }
        public bool ShouldSerializeDependencies() { return Dependencies?.Count > 0; }

        [XmlArray("compositions")]
        [XmlArrayItem("composition")]
        [ProtoMember(9)]
        public List<Composition> Compositions { get; set; }

        [XmlArray("vulnerabilities")]
        [XmlArrayItem("vulnerability")]
        [ProtoMember(10)]
        public List<Vulnerabilities.Vulnerability> Vulnerabilities { get; set; }
        public bool ShouldSerializeVulnerabilities() { return Vulnerabilities?.Count > 0; }
        
        [XmlArray("annotations")]
        [XmlArrayItem("annotation")]
        [ProtoMember(11)]
        public List<Annotation> Annotations { get; set; }
        public bool ShouldSerializeAnnotations() { return Annotations?.Count > 0; }
        
        [XmlArray("properties")]
        [XmlArrayItem("property")]
        [ProtoMember(12)]
        public List<Property> Properties { get; set; }
        public bool ShouldSerializeProperties() { return Properties?.Count > 0; }
        
        [XmlArray("formulation")]
        [XmlArrayItem("formula")]
        [ProtoMember(13)]
        public List<Formula> Formulation { get; set; }
        public bool ShouldSerializeFormulation() { return Formulation?.Count > 0; }

        // TODO: MergeWith() might be reasonable but is currently handled
        // by several strategy implementations in CycloneDX.Utils Merge.cs
        // so maybe there should be sub-classes or strategy arguments or
        // properties to select one of those implementations at run-time?..

        /// <summary>
        /// Add reference to this currently running build of cyclonedx-cli
        /// (likely) and this cyclonedx-dotnet-library into the Metadata/Tools
        /// of this Bom document. Intended for use after processing which
        /// creates or modifies the document. After all - any bugs appearing
        /// due to library routines are our own and should be trackable...
        ///
        /// NOTE: Tries to not add identical duplicate entries.
        /// </summary>
        public void BomMetadataReferThisToolkit()
        {
            // Per https://stackoverflow.com/a/36351902/4715872 :
            // Use System.Reflection.Assembly.GetExecutingAssembly()
            // to get the assembly (that this line of code is in), or
            // use System.Reflection.Assembly.GetEntryAssembly() to
            // get the assembly your project started with (most likely
            // this is your app). In multi-project solutions this is
            // something to keep in mind!
            #pragma warning disable 618
            Tool toolThisLibrary = new Tool
            {
                Vendor = "OWASP Foundation",
                Name = Assembly.GetExecutingAssembly().GetName().Name, // "cyclonedx-dotnet-library"
                Version = Assembly.GetExecutingAssembly().GetName().Version.ToString()
            };
            #pragma warning restore 618

            if (this.Metadata is null)
            {
                this.Metadata = new Metadata();
            }

            if (this.Metadata.Tools is null || this.Metadata.Tools.Tools is null)
            {
                #pragma warning disable 618
                this.Metadata.Tools = new ToolChoices
                {
                    Tools = new List<Tool>(new [] {toolThisLibrary}),
                };
                #pragma warning restore 618
            }
            else
            {
                if (!this.Metadata.Tools.Tools.Contains(toolThisLibrary))
                {
                    this.Metadata.Tools.Tools.Add(toolThisLibrary);
                }
            }

            // At worst, these would dedup away?..
            string toolThisScriptName = Assembly.GetEntryAssembly().GetName().Name; // "cyclonedx-cli" or similar
            if (toolThisScriptName != toolThisLibrary.Name)
            {
                #pragma warning disable 618
                Tool toolThisScript = new Tool
                {
                    Name = toolThisScriptName,
                    Vendor = (toolThisScriptName.ToLowerInvariant().StartsWith("cyclonedx") ? "OWASP Foundation" : null),
                    Version = Assembly.GetEntryAssembly().GetName().Version.ToString()
                };
                #pragma warning restore 618

                if (!this.Metadata.Tools.Tools.Contains(toolThisScript))
                {
                    this.Metadata.Tools.Tools.Add(toolThisScript);
                }
            }
        }

        /// <summary>
        /// Update the Metadata/Timestamp of this Bom document
        /// (after content manipulations such as a merge)
        /// using DateTime.Now.
        ///
        /// NOTE: Creates a new Metadata object to populate
        /// the property, if one was missing in this Bom object.
        /// </summary>
        public void BomMetadataUpdateTimestamp()
        {
            if (this.Metadata is null)
            {
                this.Metadata = new Metadata();
            }

            this.Metadata.Timestamp = DateTime.Now;
        }

        /// <summary>
        /// Update the SerialNumber and optionally bump the Version
        /// of a Bom document issued with such serial number (both
        /// not in the Metadata structure, but still are "meta data")
        /// of this Bom document, either using a new random UUID as
        /// the SerialNumber and assigning a Version=1, or bumping
        /// the Version -- usually done after content manipulations
        /// such as a merge, depending on their caller-defined impact.
        /// </summary>
        public void BomMetadataUpdateSerialNumberVersion(bool generateNewSerialNumber)
        {
            bool doGenerateNewSerialNumber = generateNewSerialNumber;
            if (this.Version is null || this.Version < 1 || this.SerialNumber is null || this.SerialNumber == "")
            {
                doGenerateNewSerialNumber = true;
            }

            if (doGenerateNewSerialNumber)
            {
                this.Version = 1;
                this.SerialNumber = "urn:uuid:" + System.Guid.NewGuid().ToString();
            }
            else
            {
                this.Version++;
            }
        }

        /// <summary>
        /// Set up (default or update) meta data of this Bom document,
        /// covering the Version, SerialNumber and Metadata/Timestamp
        /// in one shot. Typically useful to brush up a `new Bom()` or
        /// to ensure a new identity for a modified Bom document.
        ///
        /// NOTE: caller may want to BomMetadataReferThisToolkit()
        /// separately, to add the Metadata/Tools[] entries about this
        /// CycloneDX library and its consumer (e.g. the "cyclonedx-cli"
        /// program).
        /// </summary>
        public void BomMetadataUpdate(bool generateNewSerialNumber)
        {
            this.BomMetadataUpdateSerialNumberVersion(generateNewSerialNumber);
            this.BomMetadataUpdateTimestamp();
        }

        /// <summary>
        /// Prepare a BomWalkResult discovery report starting from
        /// this Bom document. Callers can cache it to re-use for
        /// repetitive operations.
        /// </summary>
        /// <returns></returns>
        public BomWalkResult WalkThis()
        {
            BomWalkResult res = new BomWalkResult();
            res.reset(this);

            // Note: passing "container=null" should be safe here, as
            // long as this Bom type does not have a BomRef property.
            res.SerializeBomEntity_BomRefs(this, null);

            return res;
        }

        /// <summary>
        /// Provide a Dictionary whose keys are container BomEntities
        /// and values are lists of one or more directly contained
        /// entities with a BomRef attribute, e.g. the Bom itself and
        /// the Components in it; or the Metadata and the Component
        /// description in it; or certain Components or Tools with a
        /// set of further "structural" components.
        ///
        /// The assumption per CycloneDX spec, not directly challenged
        /// in this method, is that each such listed "contained entity"
        /// (likely Component instances) has an unique BomRef value across
        /// the whole single Bom document. Other Bom documents may however
        /// have the same BomRef value (trivially "1", "2", ...) which
        /// is attached to description of an unrelated entity. This can
        /// impact such operations as a FlatMerge() of different Boms.
        ///
        /// See also: GetBomRefsWithContainer() with transposed returns.
        /// </summary>
        /// <returns></returns>
        public Dictionary<BomEntity, List<BomEntity>> GetBomRefsInContainers(BomWalkResult res)
        {
            if (res.bomRoot != this)
            {
                // throw?
                return null;
            }
            return res.dictRefsInContainers;
        }

        /// <summary>
        /// This is a run-once method to get a dictionary.
        /// See GetBomRefsInContainers(BomWalkResult) for one using a cache
        /// prepared by WalkThis() for mass manipulations.
        /// </summary>
        /// <returns></returns>
        public Dictionary<BomEntity, List<BomEntity>> GetBomRefsInContainers()
        {
            BomWalkResult res = WalkThis();
            return GetBomRefsInContainers(res);
        }

        /// <summary>
        /// Provide a Dictionary whose keys are "contained" entities
        /// with a BomRef attribute and values are their direct
        /// container BomEntities, e.g. each Bom.Components[] list
        /// entry referring the Bom itself; or the Metadata.Component
        /// entry referring the Metadata; or further "structural"
        /// components in certain Component or Tool entities.
        ///
        /// The assumption per CycloneDX spec, not directly challenged
        /// in this method, is that each such listed "contained entity"
        /// (likely Component instances) has an unique BomRef value across
        /// the whole single Bom document. Other Bom documents may however
        /// have the same BomRef value (trivially "1", "2", ...) which
        /// is attached to description of an unrelated entity. This can
        /// impact such operations as a FlatMerge() of different Boms.
        ///
        /// See also: GetBomRefsInContainers() with transposed returns.
        /// </summary>
        /// <returns></returns>
        public Dictionary<BomEntity, BomEntity> GetBomRefsWithContainer(BomWalkResult res)
        {
            if (res.bomRoot != this)
            {
                // throw?
                return null;
            }
            return res.GetBomRefsWithContainer();
        }

        /// <summary>
        /// This is a run-once method to get a dictionary.
        /// See GetBomRefsWithContainer(BomWalkResult) for one using a cache
        /// prepared by WalkThis() for mass manipulations.
        /// </summary>
        /// <returns></returns>
        public Dictionary<BomEntity, BomEntity> GetBomRefsWithContainer()
        {
            BomWalkResult res = WalkThis();
            return res.GetBomRefsWithContainer();
        }

        /// <summary>
        /// Rename all occurrences of the "BomRef" (its value definition
        /// to name an entity, if present in this Bom document, and the
        /// references to it from other entities).
        ///
        /// This version of the method considers a cache of information
        /// about current BomEntity relationships in this document, as
        /// prepared by an earlier call to GetBomRefsWithContainer() and
        /// cached by caller (may speed up the loops in case of massive
        /// processing).
        /// </summary>
        /// <param name="oldRef">Old value of BomRef</param>
        /// <param name="newRef">New value of BomRef</param>
        /// <param name="dict">Cached output of earlier GetBomRefsWithContainer();
        ///     contents of the cache can change due to successful renaming
        ///     to keep reflecting BomEntity relations in this document.
        /// </param>
        /// <returns>
        ///     False if had no hits, had collisions, etc.;
        ///     True if renamed something without any errors.
        ///
        ///     TODO: throw Exceptions instead of False,
        ///     to help callers discern the error cases?
        /// </returns>
        public bool RenameBomRef(string oldRef, string newRef, BomWalkResult res)
        {
            return false;
        }

        /// <summary>
        /// See related method
        ///     RenameBomRef(string oldRef, string newRef, Dictionary<BomEntity, BomEntity> dict)
        /// for details.
        ///
        /// This version of the method prepares and discards the helper
        /// dictionary with mapping of cross-referencing entities, and
        /// is easier to use in code for single-use cases but is less
        /// efficient for massive processing loops.
        /// </summary>
        /// <param name="oldRef">Old value of BomRef</param>
        /// <param name="newRef">New value of BomRef</param>
        /// <returns>False if had no hits; True if renamed something without any errors</returns>
        public bool RenameBomRef(string oldRef, string newRef)
        {
            BomWalkResult res = WalkThis();
            return this.RenameBomRef(oldRef, newRef, res);
        }
    }
    /// <summary>
    /// Helper class for Bom.GetBomRefsInContainers() et al discovery tracking.
    /// </summary>
    public class BomWalkResult
    {
        /// <summary>
        /// The BomEntity (normally a whole Bom document)
        /// which was walked and reported here.
        /// </summary>
        public BomEntity bomRoot = null;

        /// <summary>
        /// Populated by GetBomRefsInContainers(),
        /// keys are "container" entities and values
        /// are lists of "contained" entities which
        /// have a BomRef or equivalent property.
        /// </summary>
        readonly public Dictionary<BomEntity, List<BomEntity>> dictRefsInContainers = new Dictionary<BomEntity, List<BomEntity>>();

        /// <summary>
        /// Populated by GetBomRefsInContainers(),
        /// keys are "Ref" or equivalent string values
        /// which link back to a "BomRef" hopefully
        /// defined somewhere in the same Bom document
        /// (but may be dangling, or sometimes co-opted
        /// with external links to other Bom documents!),
        /// and values are lists of entities which use
        /// this same "ref" value.
        /// </summary>
        readonly public Dictionary<String, List<BomEntity>> dictBackrefs = new Dictionary<String, List<BomEntity>>();

        // Helpers for performance accounting - how hard
        // was it to discover the information in this
        // BomWalkResult object?
        private int sbeCountMethodEnter { get; set; }
        private int sbeCountMethodQuickExit { get; set; }
        private int sbeCountPropInfoEnter { get; set; }
        private int sbeCountPropInfoQuickExit { get; set; }
        private int sbeCountPropInfoQuickExit2 { get; set; }
        private int sbeCountPropInfo { get; set; }
        private int sbeCountPropInfo_EvalIsBomref { get; set; }
        private int sbeCountPropInfo_EvalIsNotBomref { get; set; }
        private int sbeCountPropInfo_EvalXMLAttr { get; set; }
        private int sbeCountPropInfo_EvalJSONAttr { get; set; }
        private int sbeCountPropInfo_EvalList { get; set; }
        private int sbeCountPropInfo_EvalListQuickExit { get; set; }
        private int sbeCountPropInfo_EvalListWalk { get; set; }
        private int sbeCountNewBomRefCheckDict { get; set; }
        private int sbeCountNewBomRef { get; set; }

        // This one is null, outermost loop makes a new instance, starts and stops it:
        private Stopwatch stopWatchWalkTotal = null;
        private Stopwatch stopWatchEvalAttr = new Stopwatch();
        private Stopwatch stopWatchNewBomref = new Stopwatch();
        private Stopwatch stopWatchNewBomrefCheck = new Stopwatch();
        private Stopwatch stopWatchNewBomrefNewListSpawn = new Stopwatch();
        private Stopwatch stopWatchNewBomrefNewListInDict = new Stopwatch();
        private Stopwatch stopWatchNewBomrefListAdd = new Stopwatch();
        private Stopwatch stopWatchGetValue = new Stopwatch();

        public void reset()
        {
            dictRefsInContainers.Clear();
            dictBackrefs.Clear();

            sbeCountMethodEnter = 0;
            sbeCountMethodQuickExit = 0;
            sbeCountPropInfoEnter = 0;
            sbeCountPropInfoQuickExit = 0;
            sbeCountPropInfoQuickExit2 = 0;
            sbeCountPropInfo = 0;
            sbeCountPropInfo_EvalIsBomref = 0;
            sbeCountPropInfo_EvalIsNotBomref = 0;
            sbeCountPropInfo_EvalXMLAttr = 0;
            sbeCountPropInfo_EvalJSONAttr = 0;
            sbeCountPropInfo_EvalList = 0;
            sbeCountPropInfo_EvalListQuickExit = 0;
            sbeCountPropInfo_EvalListWalk = 0;
            sbeCountNewBomRefCheckDict = 0;
            sbeCountNewBomRef = 0;

            bomRoot = null;
            stopWatchWalkTotal = null;
            stopWatchEvalAttr = new Stopwatch();
            stopWatchNewBomref = new Stopwatch();
            stopWatchNewBomrefCheck = new Stopwatch();
            stopWatchNewBomrefNewListSpawn = new Stopwatch();
            stopWatchNewBomrefNewListInDict = new Stopwatch();
            stopWatchNewBomrefListAdd = new Stopwatch();
            stopWatchGetValue = new Stopwatch();
        }

        public void reset(BomEntity newRoot)
        {
            this.reset();
            this.bomRoot = newRoot;
        }

        private static string StopWatchToString(Stopwatch stopwatch)
        {
            string elapsed = "N/A";
            if (stopwatch != null)
            {
                // Get the elapsed time as a TimeSpan value.
                TimeSpan ts = stopwatch.Elapsed;
                elapsed = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                    ts.Hours, ts.Minutes, ts.Seconds,
                    ts.Milliseconds / 10);
            }
            return elapsed;
        }

        public override string ToString()
        {
            return "BomWalkResult: " +
                $"Timing.WalkTotal={StopWatchToString(stopWatchWalkTotal)} " +
                $"sbeCountMethodEnter={sbeCountMethodEnter} " +
                $"sbeCountMethodQuickExit={sbeCountMethodQuickExit} " +
                $"sbeCountPropInfoEnter={sbeCountPropInfoEnter} " +
                $"sbeCountPropInfoQuickExit={sbeCountPropInfoQuickExit} " +
                $"Timing.GetValue={StopWatchToString(stopWatchGetValue)} " +
                $"sbeCountPropInfo_EvalIsBomref={sbeCountPropInfo_EvalIsBomref} " +
                $"sbeCountPropInfo_EvalIsNotBomref={sbeCountPropInfo_EvalIsNotBomref} " +
                $"Timing.EvalAttr={StopWatchToString(stopWatchEvalAttr)} " +
                $"sbeCountPropInfo_EvalXMLAttr={sbeCountPropInfo_EvalXMLAttr} " +
                $"sbeCountPropInfo_EvalJSONAttr={sbeCountPropInfo_EvalJSONAttr} " +
                $"Timing.NewBomRef={StopWatchToString(stopWatchNewBomref)} (" +
                $"Timing.NewBomRefCheck={StopWatchToString(stopWatchNewBomrefCheck)} " +
                $"Timing.NewBomRefNewListSpawn={StopWatchToString(stopWatchNewBomrefNewListSpawn)} " +
                $"Timing.NewBomRefNewListInDict={StopWatchToString(stopWatchNewBomrefNewListInDict)} " +
                $"Timing.NewBomRefListAdd={StopWatchToString(stopWatchNewBomrefListAdd)}) " +
                $"sbeCountNewBomRefCheckDict={sbeCountNewBomRefCheckDict} " +
                $"sbeCountNewBomRef={sbeCountNewBomRef} " +
                $"sbeCountPropInfo_EvalList={sbeCountPropInfo_EvalList} " +
                $"sbeCountPropInfoQuickExit2={sbeCountPropInfoQuickExit2} " +
                $"sbeCountPropInfo_EvalListQuickExit={sbeCountPropInfo_EvalListQuickExit} " +
                $"sbeCountPropInfo_EvalListWalk={sbeCountPropInfo_EvalListWalk} " +
                $"sbeCountPropInfo={sbeCountPropInfo} " +
                $"dictRefsInContainers.Count={dictRefsInContainers.Count} " +
                $"dictBackrefs.Count={dictBackrefs.Count}";
        }

        /// <summary>
        /// Helper for Bom.GetBomRefsInContainers().
        /// </summary>
        /// <param name="obj">A BomEntity instance currently being investigated</param>
        /// <param name="container">A BomEntity instance whose attribute
        ///    (or member of a List<> attribute) is currently being
        ///    investigated. May be null when starting iteration
        ///    from this.GetBomRefsInContainers() method.
        /// </param>
        public void SerializeBomEntity_BomRefs(BomEntity obj, BomEntity container)
        {
            // With CycloneDX spec 1.4 or older it might be feasible to
            // walk specific properties of the Bom instance to look into
            // their contents by known class types. As seen by excerpt
            // from the spec below, just to list the locations where a
            // "bom-ref" value can be set to identify an entity or where
            // such value can be used to refer back to that entity, such
            // approach is nearly infeasible starting with CDX 1.5 -- so
            // use of reflection below is a more sustainable choice.

            // TL:DR further details:
            //
            // Looking in schema definitions search for items that should
            // be bom-refs (whether the attributes of certain entry types,
            // or back-references from whoever uses them):
            // * in "*.schema.json" search for "#/definitions/refType", or
            // * in "*.xsd" search for "bom:refType" and its super-set for
            //   certain use-cases "bom:bomReferenceType"
            // Since CDX spec 1.5 note there is also a "refLinkType" with
            // same formal syntax as "refType" but different purpose --
            // to specify back-references (as separate from identifiers
            // of new unique entries).  Also do not confuse with bomLink,
            // bomLinkDocumentType, and bomLinkElementType which refer to
            // entities in OTHER Bom documents (or those Boms themselves).
            //
            // As of CDX spec 1.4+, a "bom-ref" attribute can be specified in:
            // * (1.4, 1.5) component/"bom-ref"
            // * (1.4, 1.5) service/"bom-ref"
            // * (1.4, 1.5) vulnerability/"bom-ref"
            // * (1.5) organizationalEntity/"bom-ref"
            // * (1.5) organizationalContact/"bom-ref"
            // * (1.5) license/"bom-ref"
            // * (1.5) license/licenseChoice/...expression.../"bom-ref"
            // * (1.5) componentEvidence/occurrences[]/"bom-ref"
            // * (1.5) compositions/"bom-ref"
            // * (1.5) annotations/"bom-ref"
            // * (1.5) modelCard/"bom-ref"
            // * (1.5) componentData/"bom-ref"
            // * (1.5) formula/"bom-ref"
            // * (1.5) workflow/"bom-ref"
            // * (1.5) task/"bom-ref"
            // * (1.5) workspace/"bom-ref"
            // * (1.5) trigger/"bom-ref"
            // and referred from:
            // * dependency/"ref" => only "component" (1.4), or
            //   "component or service" (since 1.5)
            // * dependency/"dependsOn[]" => only "component" (1.4),
            //   or "component or service" (since 1.5)
            // * (1.4, 1.5) compositions/"assemblies[]" => "component or service"
            // * (1.4, 1.5) compositions/"dependencies[]" => "component or service"
            // * (1.4, 1.5) vulnerability/affects/items/"ref" => "component or service"
            // * (1.5) componentEvidence/identity/tools[] => any, see spec
            // * (1.5) annotations/subjects[] => any
            // * (1.5) modelCard/modelParameters/datasets[]/"ref" => "data component" (see "#/definitions/componentData")
            // * (1.5) resourceReferenceChoice/"ref" => any
            //
            // Notably, CDX 1.5 also introduces resourceReferenceChoice
            // which generalizes internal or external references, used in:
            // * (1.5) workflow/resourceReferences[]
            // * (1.5) task/resourceReferences[]
            // * (1.5) workspace/resourceReferences[]
            // * (1.5) trigger/resourceReferences[]
            // * (1.5) event/{source,target}
            // * (1.5) {inputType,outputType}/{source,target,resource}
            // The CDX 1.5 tasks, workflows etc. also can reference each other.
            //
            // In particular, "component" instances (e.g. per JSON
            // "#/definitions/component" spec search) can be direct
            // properties (or property arrays) in:
            // * (1.4, 1.5) component/pedigree/{ancestors,descendants,variants}
            // * (1.4, 1.5) component/components[] -- structural hierarchy (not dependency tree)
            // * (1.4, 1.5) bom/components[]
            // * (1.4, 1.5) bom/metadata/component -- 0 or 1 item about the Bom itself
            // * (1.5) bom/metadata/tools/components[] -- SW and HW tools used to create the Bom
            // * (1.5) vulnerability/tools/components[] -- SW and HW tools used to describe the vuln
            // * (1.5) formula/components[]
            //
            // Note that there may be potentially any level of nesting of
            // components in components, and compositions, among other things.
            //
            // And "service" instances (per JSON "#/definitions/service"):
            // * (1.4, 1.5) service/services[]
            // * (1.4, 1.5) bom/services[]
            // * (1.5) bom/metadata/tools/services[] -- services as tools used to create the Bom
            // * (1.5) vulnerability/tools/services[] -- services as tools used to describe the vuln
            // * (1.5) formula/services[]
            //
            // The CDX spec 1.5 also introduces "annotation" which can refer to
            // such bom-ref carriers as service, component, organizationalEntity,
            // organizationalContact.
            sbeCountMethodEnter++;

            if (obj is null)
            {
                sbeCountMethodQuickExit++;
                return;
            }

            Type objType = obj.GetType();

            // Sanity-check: we do not recurse into non-BomEntity types.
            // Hopefully the compiler or runtime would not have let other obj's in...
            if (objType is null || (!(typeof(BomEntity).IsAssignableFrom(objType))))
            {
                sbeCountMethodQuickExit++;
                return;
            }

            bool isTimeAccounter = (stopWatchWalkTotal is null);
            if (isTimeAccounter)
            {
                stopWatchWalkTotal = new Stopwatch();
                stopWatchWalkTotal.Start();
            }

            // Looking up (comparing) keys in dictRefsInContainers[] is prohibitively
            // expensive (may have to do with serialization into a string to implement
            // GetHashCode() method), so we minimize interactions with that codepath.
            // General assumption that we only look at same container once, but the
            // code should cope with more visits (possibly at a cost).
            List<BomEntity> containerList = null;

            // TODO: Prepare a similar cache with only a subset of
            // properties of interest for bom-ref search, to avoid
            // looking into known dead ends in a loop.
            PropertyInfo[] objProperties = BomEntity.KnownEntityTypeProperties[objType];
            if (objProperties.Length < 1)
            {
                objProperties = objType.GetProperties(BindingFlags.GetProperty | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            }
            foreach (PropertyInfo propInfo in objProperties)
            {
                sbeCountPropInfoEnter++;

                // We do not recurse into non-BomEntity types
                if (propInfo is null)
                {
                    // Is this expected? Maybe throw?
                    sbeCountPropInfoQuickExit++;
                    continue;
                }

                Type propType = propInfo.PropertyType;
                stopWatchGetValue.Start();
                if (propInfo.Name.StartsWith("NonNullable")) {
                    // It is a getter/setter-wrapped facade
                    // of a Nullable<T> for some T - skip,
                    // we would inspect the raw item instead
                    // (factual nulls would cause an exception
                    // and require a try/catch overhead here).
                    // FIXME: Is there an attribute for this,
                    // to avoid a string comparison in a loop?
                    sbeCountPropInfoQuickExit++;
                    stopWatchGetValue.Stop();
                    continue;
                }
                var propVal = propInfo.GetValue(obj, null);
                stopWatchGetValue.Stop();

                if (propVal is null)
                {
                    sbeCountPropInfoQuickExit++;
                    continue;
                }

                // If the type of current "obj" contains a "bom-ref", or
                // has annotations like [JsonPropertyName("bom-ref")] and
                // [XmlAttribute("bom-ref")], save it into the dictionary.

                // TODO: Pedantically it would be better to either parse
                // and consult corresponding CycloneDX spec, somehow, for
                // properties which have needed schema-defined type (see
                // detailed comments in GetBomRefsInContainers() method).
                sbeCountPropInfo_EvalIsBomref++;
                bool propIsBomRef = (propType.GetTypeInfo().IsAssignableFrom(typeof(string)) && propInfo.Name == "BomRef");
                if (!propIsBomRef)
                {
                    sbeCountPropInfo_EvalIsNotBomref++;
                }
                if (!propIsBomRef)
                {
                    sbeCountPropInfo_EvalXMLAttr++;
                    stopWatchEvalAttr.Start();
                    object[] attrs = propInfo.GetCustomAttributes(typeof(XmlAttribute), false);
                    if (attrs.Length > 0)
                    {
                        propIsBomRef = (Array.Find(attrs, x => ((XmlAttribute)x).Name == "bom-ref") != null);
                    }
                    stopWatchEvalAttr.Stop();
                }
                if (!propIsBomRef)
                {
                    sbeCountPropInfo_EvalJSONAttr++;
                    stopWatchEvalAttr.Start();
                    object[] attrs = propInfo.GetCustomAttributes(typeof(JsonPropertyNameAttribute), false);
                    if (attrs.Length > 0)
                    {
                        propIsBomRef = (Array.Find(attrs, x => ((JsonPropertyNameAttribute)x).Name == "bom-ref") != null);
                    }
                    stopWatchEvalAttr.Stop();
                }

                if (propIsBomRef)
                {
                    // Save current object into tracking, and be done with this prop!
                    stopWatchNewBomref.Start();
                    if (containerList is null)
                    {
                        sbeCountNewBomRefCheckDict++;
                        stopWatchNewBomrefCheck.Start();
                        // "proper" dict key lookup probably goes via hashes
                        // which go via serialization for BomEntity classes,
                        // and so walking a Bom with a hundred Components
                        // takes a second with "apparent" loop like:
                        //    if (dictRefsInContainers.TryGetValue(container, out List<BomEntity> list))
                        // but takes miniscule fractions as it should, when
                        // we avoid hashing like this (and also maintain
                        // consistent references if original objects get
                        // modified - so serialization and hash changes;
                        // this should not happen in this loop, and the
                        // intention is to keep tabs on references to all
                        // original objects so we can rename what we need):
                        foreach (var (cont, list) in dictRefsInContainers)
                        {
                            if (Object.ReferenceEquals(container, cont))
                            {
                                containerList = list;
                                break;
                            }
                        }
                        stopWatchNewBomrefCheck.Stop();

                        if (containerList is null)
                        {
                            stopWatchNewBomrefNewListSpawn.Start();
                            containerList = new List<BomEntity>();
                            stopWatchNewBomrefNewListSpawn.Stop();
                            stopWatchNewBomrefNewListInDict.Start();
                            dictRefsInContainers[container] = containerList;
                            stopWatchNewBomrefNewListInDict.Stop();
                        }
                    }

                    sbeCountNewBomRef++;
                    stopWatchNewBomrefListAdd.Start();
                    containerList.Add((BomEntity)obj);
                    stopWatchNewBomrefListAdd.Stop();
                    stopWatchNewBomref.Stop();

                    // Done with this string property, look at next
                    continue;
                }

                // We do not recurse into non-BomEntity types
                sbeCountPropInfo_EvalList++;
                bool propIsListBomEntity = (
                    (propType.GetTypeInfo().ImplementedInterfaces.Contains(typeof(System.Collections.IList)))
                    && (Array.Find(propType.GetTypeInfo().GenericTypeArguments,
                        x => typeof(BomEntity).GetTypeInfo().IsAssignableFrom(x.GetTypeInfo())) != null)
                );

                if (!(
                    propIsListBomEntity
                    || (typeof(BomEntity).GetTypeInfo().IsAssignableFrom(propType.GetTypeInfo()))
                ))
                {
                    // Not a BomEntity or (potentially) a List of those
                    sbeCountPropInfoQuickExit2++;
                    continue;
                }

                if (propIsListBomEntity)
                {
                    // Use cached info where available
                    PropertyInfo listPropCount = null;
                    MethodInfo listMethodGetItem = null;
                    MethodInfo listMethodAdd = null;
                    if (BomEntity.KnownEntityTypeLists.TryGetValue(propType, out BomEntityListReflection refInfo))
                    {
                        listPropCount = refInfo.propCount;
                        listMethodGetItem = refInfo.methodGetItem;
                        listMethodAdd = refInfo.methodAdd;
                    }
                    else
                    {
                        // No cached info about BomEntityListReflection[{propType}
                        listPropCount = propType.GetProperty("Count");
                        listMethodGetItem = propType.GetMethod("get_Item");
                        listMethodAdd = propType.GetMethod("Add");
                    }

                    if (listMethodGetItem == null || listPropCount == null || listMethodAdd == null)
                    {
                        // Should not have happened, but...
                        sbeCountPropInfo_EvalListQuickExit++;
                        continue;
                    }

                    int propValCount = (int)listPropCount.GetValue(propVal, null);
                    if (propValCount < 1)
                    {
                        // Empty list
                        sbeCountPropInfo_EvalListQuickExit++;
                        continue;
                    }

                    sbeCountPropInfo_EvalListWalk++;
                    for (int o = 0; o < propValCount; o++)
                    {
                        var listVal = listMethodGetItem.Invoke(propVal, new object[] { o });
                        if (listVal is null)
                        {
                            continue;
                        }

                        if (!(listVal is BomEntity))
                        {
                            break;
                        }

                        SerializeBomEntity_BomRefs((BomEntity)listVal, obj);
                    }

                    // End of list, or a break per above
                    continue;
                }

                sbeCountPropInfo++;
                SerializeBomEntity_BomRefs((BomEntity)propVal, obj);
            }

            if (isTimeAccounter)
            {
                stopWatchWalkTotal.Stop();
            }
        }

        /// <summary>
        /// Provide a Dictionary whose keys are container BomEntities
        /// and values are lists of one or more directly contained
        /// entities with a BomRef attribute, e.g. the Bom itself and
        /// the Components in it; or the Metadata and the Component
        /// description in it; or certain Components or Tools with a
        /// set of further "structural" components.
        ///
        /// The assumption per CycloneDX spec, not directly challenged
        /// in this method, is that each such listed "contained entity"
        /// (likely Component instances) has an unique BomRef value across
        /// the whole single Bom document. Other Bom documents may however
        /// have the same BomRef value (trivially "1", "2", ...) which
        /// is attached to description of an unrelated entity. This can
        /// impact such operations as a FlatMerge() of different Boms.
        ///
        /// See also: GetBomRefsWithContainer() with transposed returns.
        /// </summary>
        /// <returns></returns>
        public Dictionary<BomEntity, List<BomEntity>> GetBomRefsInContainers()
        {
            return dictRefsInContainers;
        }

        /// <summary>
        /// Provide a Dictionary whose keys are "contained" entities
        /// with a BomRef attribute and values are their direct
        /// container BomEntities, e.g. each Bom.Components[] list
        /// entry referring the Bom itself; or the Metadata.Component
        /// entry referring the Metadata; or further "structural"
        /// components in certain Component or Tool entities.
        ///
        /// The assumption per CycloneDX spec, not directly challenged
        /// in this method, is that each such listed "contained entity"
        /// (likely Component instances) has an unique BomRef value across
        /// the whole single Bom document. Other Bom documents may however
        /// have the same BomRef value (trivially "1", "2", ...) which
        /// is attached to description of an unrelated entity. This can
        /// impact such operations as a FlatMerge() of different Boms.
        ///
        /// See also: GetBomRefsInContainers() with transposed returns.
        /// </summary>
        /// <returns></returns>
        public Dictionary<BomEntity, BomEntity> GetBomRefsWithContainer()
        {
            Dictionary<BomEntity, BomEntity> dictWithC = new Dictionary<BomEntity, BomEntity>();

            foreach (var (container, listItems) in dictRefsInContainers)
            {
                if (listItems is null || container is null || listItems.Count < 1) {
                    continue;
                }

                foreach (var item in listItems) {
                    dictWithC[item] = container;
                }
            }

            return dictWithC;
        }
    }
}
