﻿// This file is part of CycloneDX Library for .NET
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
using System.Diagnostics.Contracts;
using System.Text.Json;
using System.Text.Json.Serialization;
using ComponentScope = CycloneDX.Models.Component.ComponentScope;

namespace CycloneDX.Json.Converters
{

    public class ComponentScopeConverter : JsonConverter<ComponentScope>
    {
        public override ComponentScope Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Null
                || reader.TokenType != JsonTokenType.String)
            {
                throw new JsonException();
            }

            var componentScopeString = reader.GetString();

            ComponentScope componentScope;
            var success = Enum.TryParse<ComponentScope>(componentScopeString, ignoreCase: true, out componentScope);
            if (success)
            {
                return componentScope;
            }
            else
            {
                throw new JsonException();
            }
        }

        public override void Write(
            Utf8JsonWriter writer,
            ComponentScope value,
            JsonSerializerOptions options)
        {
            Contract.Requires(writer != null);
            writer.WriteStringValue(value.ToString().ToLowerInvariant());
        }
    }
}
