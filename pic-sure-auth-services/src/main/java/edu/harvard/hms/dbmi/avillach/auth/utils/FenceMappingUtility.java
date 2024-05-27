package edu.harvard.hms.dbmi.avillach.auth.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Singleton
@Startup
public class FenceMappingUtility {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private Map<String, Map> fenceMappingByConsent;
    private Map<String, Map> fenceMappingByAuthZ;
    private static String templatePath;
    private ObjectMapper objectMapper;

    @PostConstruct
    public void init() {
        try {
            Context ctx = new InitialContext();
            templatePath = (String) ctx.lookup("java:global/templatePath");
            objectMapper = new ObjectMapper();

            initializeFENCEMappings();
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }

    private synchronized void initializeFENCEMappings() {
        if (fenceMappingByConsent == null || fenceMappingByAuthZ == null) {
            ArrayList<Map> studies = loadBioDataCatalystFenceMappingData();
            ConcurrentHashMap<String, Map> tempFenceMappingByConsent = new ConcurrentHashMap<>();
            ConcurrentHashMap<String, Map> tempFenceMappingByAuthZ = new ConcurrentHashMap<>();

            studies.parallelStream().forEach(study -> {
                String consentVal = (study.get("consent_group_code") != null && !study.get("consent_group_code").toString().isEmpty()) ?
                        study.get("study_identifier") + "." + study.get("consent_group_code") :
                        study.get("study_identifier").toString();
                tempFenceMappingByConsent.put(consentVal, study);
                tempFenceMappingByAuthZ.put(study.get("authZ").toString().replace("\\/", "/"), study);
            });

            fenceMappingByConsent = Collections.unmodifiableMap(tempFenceMappingByConsent);
            fenceMappingByAuthZ = Collections.unmodifiableMap(tempFenceMappingByAuthZ);
        }
    }

    public Map<String, Map> getFENCEMapping() {
        return fenceMappingByConsent;
    }

    public Map<String, Map> getFenceMappingByAuthZ() {
        return fenceMappingByAuthZ;
    }

    private ArrayList<Map> loadBioDataCatalystFenceMappingData() {
        Map fenceMapping;
        ArrayList<Map> studies;
        try {
            logger.debug("getFENCEMapping: loading FENCE mapping from {}", templatePath);
            fenceMapping = objectMapper.readValue(
                    new File(String.join(File.separator,
                            new String[]{templatePath, "fence_mapping.json"}))
                    , Map.class);

            studies = (ArrayList<Map>) fenceMapping.get("bio_data_catalyst");
            logger.debug("getFENCEMapping: found FENCE mapping with {} entries", studies.size());
        } catch (Exception e) {
            logger.error("loadFenceMappingData: Non-fatal error parsing fence_mapping.json: {}", templatePath, e);
            return new ArrayList<>();
        }
        return studies;
    }

}
