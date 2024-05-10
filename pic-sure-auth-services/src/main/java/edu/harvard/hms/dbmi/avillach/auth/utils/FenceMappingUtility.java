package edu.harvard.hms.dbmi.avillach.auth.utils;

import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Singleton
@Startup
public class FenceMappingUtility {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private Map<String, Map> _projectMap;
    private Map<String, Map> fenceMappingByAuthZ;

    @PostConstruct
    public void init() {
        try {
            initializeFENCEMapping();
            initializeFenceMappingByAuthZ();
        } catch (IOException e) {
            // Handle exceptions appropriately
            logger.error("Error initializing FENCE mappings", e);
        }
    }

    private void initializeFENCEMapping() throws IOException {
        List<Map> projects = loadBioDataCatalystFenceMappingData();
        _projectMap = new HashMap<>(projects.size());
        for (Map project : projects) {
            String consentVal = (project.get("consent_group_code") != null && project.get("consent_group_code") != "") ?
                    project.get("study_identifier") + "." + project.get("consent_group_code") :
                    project.get("study_identifier").toString();
            _projectMap.put(consentVal, project);
        }
    }

    private void initializeFenceMappingByAuthZ() throws IOException {
        List<Map> projects = loadBioDataCatalystFenceMappingData();
        fenceMappingByAuthZ = new HashMap<>(projects.size());
        for (Map project : projects) {
            fenceMappingByAuthZ.put(project.get("authZ").toString().replace("\\/", "/"), project);
        }
    }

    public Map<String, Map> getFENCEMapping() {
        return _projectMap;
    }

    public Map<String, Map> getFenceMappingByAuthZ() {
        return fenceMappingByAuthZ;
    }

    private List<Map> loadBioDataCatalystFenceMappingData() {
        Map fenceMapping = null;
        List<Map> projects = null;
        try {
            fenceMapping = JAXRSConfiguration.objectMapper.readValue(
                    new File(String.join(File.separator,
                            new String[] {JAXRSConfiguration.templatePath ,"fence_mapping.json"}))
                    , Map.class);

            projects = (List<Map>) fenceMapping.get("bio_data_catalyst");
            logger.debug("getFENCEMapping: found FENCE mapping with {} entries", projects.size());
        } catch (Exception e) {
            logger.error("loadFenceMappingData: Non-fatal error parsing fence_mapping.json: {}", JAXRSConfiguration.templatePath, e);
            return Collections.singletonList(new HashMap());
        }
        return projects;
    }

}
