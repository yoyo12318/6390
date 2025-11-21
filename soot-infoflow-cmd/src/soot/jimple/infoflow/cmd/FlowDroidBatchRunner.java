package soot.jimple.infoflow.cmd;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.taintWrappers.EasyTaintWrapper;

public class FlowDroidBatchRunner {

    public static void main(String[] args) {
        // Configuration - Hardcoded as per the user's environment in run_flowdroid.ps1
        String apkDir = "F:\\数据\\Malgenome\\ADRD";
        String androidJars = "C:\\Users\\86188\\AppData\\Local\\Android\\Sdk\\platforms";
        String outputDir = "xml-output";
        // Adjusted paths to be relative to soot-infoflow-cmd directory or absolute
        String sourceSinkFile = "../soot-infoflow-android/SourcesAndSinks.txt";
        
        // Temp files to handle potential encoding issues
        String tempApkName = "temp_analysis_lib.apk";
        String tempXmlName = "temp_analysis_lib.xml";

        File apkDirectory = new File(apkDir);
        if (!apkDirectory.exists() || !apkDirectory.isDirectory()) {
            System.err.println("APK directory not found: " + apkDir);
            return;
        }

        File outputDirectory = new File(outputDir);
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        File[] apkFiles = apkDirectory.listFiles((dir, name) -> name.toLowerCase().endsWith(".apk"));
        if (apkFiles == null || apkFiles.length == 0) {
            System.out.println("No APK files found in " + apkDir);
            return;
        }

        System.out.println("Found " + apkFiles.length + " APKs to process.");

        for (File apk : apkFiles) {
            System.out.println("Processing " + apk.getName() + "...");
            
            File tempApk = new File(tempApkName);
            File tempXml = new File(tempXmlName);
            
            try {
                // 1. Copy APK to temp file
                Files.copy(apk.toPath(), tempApk.toPath(), StandardCopyOption.REPLACE_EXISTING);

                // 2. Configure FlowDroid
                InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
                config.getAnalysisFileConfig().setTargetAPKFile(tempApk);
                config.getAnalysisFileConfig().setAndroidPlatformDir(new File(androidJars));
                config.getAnalysisFileConfig().setSourceSinkFile(new File(sourceSinkFile));
                config.getAnalysisFileConfig().setOutputFile(tempXml.getCanonicalPath());
                
                // Enable some common options (similar to defaults or what might be needed)
                // config.setEnableImplicitFlows(false);
                // config.setEnableStaticFieldTracking(true);
                // config.setAccessPathLength(5);
                // config.setFlowSensitiveAliasing(true);

                // 3. Setup Application
                SetupApplication app = new SetupApplication(config);
                
                // Set Taint Wrapper (using EasyTaintWrapper as a default safe choice if summariesManual isn't set up perfectly)
                // Or use the one from the snippet if "summariesManual" exists.
                // app.setTaintWrapper(new SummaryTaintWrapper(new LazySummaryProvider("summariesManual")));
                // Using EasyTaintWrapper with the provided file in the workspace if available, or default.
                // The workspace has soot-infoflow/EasyTaintWrapperSource.txt
                File twSource = new File("../soot-infoflow/EasyTaintWrapperSource.txt");
                if (twSource.exists()) {
                    app.setTaintWrapper(new EasyTaintWrapper(twSource));
                } else {
                    // Fallback or skip if not found
                    System.out.println("Warning: EasyTaintWrapperSource.txt not found, running without taint wrapper or using default.");
                }

                // 4. Run Analysis
                InfoflowResults results = app.runInfoflow();
                
                // 5. Move output XML to final destination
                if (tempXml.exists()) {
                    String finalXmlName = apk.getName().substring(0, apk.getName().lastIndexOf('.')) + ".xml";
                    Path finalXmlPath = Paths.get(outputDir, finalXmlName);
                    Files.move(tempXml.toPath(), finalXmlPath, StandardCopyOption.REPLACE_EXISTING);
                    System.out.println("Analysis finished. Output saved to " + finalXmlPath.toString());
                } else {
                    System.err.println("Error: Analysis failed for " + apk.getName() + " (No output XML generated)");
                }

            } catch (RuntimeException e) {
                if (e.getMessage() != null && e.getMessage().contains("cannot set active body for phantom class")) {
                    System.err.println("Error analyzing " + apk.getName() + ": Phantom class error (likely missing Android SDK platform or library). Skipping.");
                } else {
                    System.err.println("Exception analyzing " + apk.getName() + ": " + e.getMessage());
                    e.printStackTrace();
                }
            } catch (Exception e) {
                System.err.println("Exception analyzing " + apk.getName() + ": " + e.getMessage());
                e.printStackTrace();
            } finally {
                // 6. Cleanup
                try {
                    if (tempApk.exists()) Files.delete(tempApk.toPath());
                    // tempXml is moved, but if it still exists (copy instead of move?), delete it.
                    if (tempXml.exists()) Files.delete(tempXml.toPath()); 
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        System.out.println("All APKs processed.");
        System.exit(0);
    }
}
