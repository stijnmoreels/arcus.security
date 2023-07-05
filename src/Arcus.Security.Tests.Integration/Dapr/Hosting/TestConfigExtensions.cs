﻿using System;
using System.Collections.Generic;
using System.IO;
using GuardNet;
using Microsoft.Extensions.Configuration;

// ReSharper disable once CheckNamespace
namespace Arcus.Security.Tests.Integration.Fixture
{
    /// <summary>
    /// Extensions on the <see cref="TestConfig"/> for easier access to the Dapr-related information.
    /// </summary>
    public static class TestConfigExtensions
    {
        /// <summary>
        /// Gets the local file path of the Dapr installation on this system where the tests are run.
        /// </summary>
        /// <param name="configuration">The integration test configuration.</param>
        /// <exception cref="ArgumentException">Thrown when the <paramref name="configuration"/> is <c>null</c>.</exception>
        /// <exception cref="KeyNotFoundException">Thrown when there is no Dapr installation file path present in the application settings.</exception>
        /// <exception cref="FileNotFoundException">Thrown when a Dapr installation on the system where the tests are running cannot be found.</exception>
        public static FileInfo GetDaprInstallationFilePath(this TestConfig configuration)
        {
            Guard.NotNull(configuration, nameof(configuration));

            var key = "Arcus:Dapr:DaprBin";
            string filePath = configuration.GetValue<string>(key);
            
            if (string.IsNullOrWhiteSpace(filePath))
            {
                throw new KeyNotFoundException(
                    "Could not find the installation file path of the Dapr Sidecar in the local app settings" 
                    + "please install the Dapr Sidecar on this machine (https://docs.dapr.io/getting-started/install-dapr-cli/) "
                    + $"and add the installation folder as configuration key '{key}' to your local app settings");
            }

            if (filePath.StartsWith("#{") && filePath.EndsWith("}#"))
            {
                throw new KeyNotFoundException(
                    $"Could not find the installation file path of the Dapr Sidecar in the local app settings because the appsettings token '{filePath}' is not yet replaced," 
                    + "please install the Dapr Sidecar on this machine (https://docs.dapr.io/getting-started/install-dapr-cli/) "
                    + $"and add the installation folder as configuration key '{key}' to your local app settings");
            }

            FileInfo file;
            try
            {
                file = new FileInfo(filePath);
            }
            catch (Exception exception)
            {
                throw new FileNotFoundException(
                    $"Could not find file path returned for key '{key}' because it doesn't point to valid Dapr Sidecar execution file, " 
                    + "please install the Dapr Sidecar on this machine (https://docs.dapr.io/getting-started/install-dapr-cli/) " 
                    + $"and add the installation folder as configuration key '{key}' to your local app settings", exception);
            }

            if (!file.Exists || !file.Name.StartsWith("dapr"))
            {
                throw new FileNotFoundException(
                    $"Could not find file path returned for key '{key}' because it doesn't point to valid Dapr Sidecar execution file ('dapr'), " 
                    + "please install the Dapr Sidecar on this machine (https://docs.dapr.io/getting-started/install-dapr-cli/) " 
                    + $"and add the installation folder as configuration key '{key}' to your local app settings");
            }

            return file;
        }
    }
}
