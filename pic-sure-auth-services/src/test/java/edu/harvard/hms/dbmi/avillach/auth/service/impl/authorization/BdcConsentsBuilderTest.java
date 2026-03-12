package edu.harvard.hms.dbmi.avillach.auth.service.impl.authorization;


import edu.harvard.hms.dbmi.avillach.auth.model.fenceMapping.StudyMetaData;
import edu.harvard.hms.dbmi.avillach.auth.model.ras.RasDbgapPermission;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class BdcConsentsBuilderTest {

    private static final Map<String, StudyMetaData> DEFAULT_FENCE_MAPPING = Map.of(
        "phs123.c1", new StudyMetaData().setHarmonized(false).setDataType("P"), "phs123.c2",
        new StudyMetaData().setHarmonized(false).setDataType("P"), "phs456.c1", new StudyMetaData().setHarmonized(true).setDataType("P"),
        "phs456.c2", new StudyMetaData().setHarmonized(true).setDataType("P"), "phs789.c1",
        new StudyMetaData().setHarmonized(false).setDataType("G"), "phs789.c2", new StudyMetaData().setHarmonized(false).setDataType("G"),
        "phs999.c1", new StudyMetaData().setHarmonized(true).setDataType("G"), "phs999.c2",
        new StudyMetaData().setHarmonized(true).setDataType("G"), "open_access-1000Genomes",
        new StudyMetaData().setHarmonized(false).setDataType("P").setStudyType("public"), "tutorial-biolincc_framingham",
        new StudyMetaData().setHarmonized(false).setDataType("P").setStudyType("public")
    );

    @Test
    public void createConsents_noConsents_addPublic() {
        // TODO: test NO consents does not allow full access
        Set<RasDbgapPermission> dbgapPermissions = Set.of();
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(Set.of(BdcConsentsBuilder.CONSENTS_KEY), consents.keySet());
        assertEquals(consents.get(BdcConsentsBuilder.CONSENTS_KEY), Set.of("open_access-1000Genomes", "tutorial-biolincc_framingham"));
    }

    @Test
    public void createConsents_noConsentsNoPublic_throwException() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of();
        assertThrows(
            IllegalStateException.class,
            () -> new BdcConsentsBuilder(Map.of("phs123.c1", new StudyMetaData().setHarmonized(false).setDataType("P")), dbgapPermissions)
                .createConsents()
        );
    }

    @Test
    public void createConsents_oneNormalConsent() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of(new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c1"));
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(Set.of(BdcConsentsBuilder.CONSENTS_KEY), consents.keySet());
        assertEquals(
            Set.of("phs123.c1", "open_access-1000Genomes", "tutorial-biolincc_framingham"), consents.get(BdcConsentsBuilder.CONSENTS_KEY)
        );
    }

    @Test
    public void createConsents_multipleNormalConsent() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of(
            new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c1"),
            new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c2")
        );
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(Set.of(BdcConsentsBuilder.CONSENTS_KEY), consents.keySet());
        assertEquals(
            Set.of("phs123.c1", "phs123.c2", "open_access-1000Genomes", "tutorial-biolincc_framingham"),
            consents.get(BdcConsentsBuilder.CONSENTS_KEY)
        );
    }

    @Test
    public void createConsents_oneNormalConsentOneMissingConsent_ignoreMissingConsent() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of(
            new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c1"),
            new RasDbgapPermission().setPhsId("phs321").setConsentGroup("c1")
        );
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(Set.of(BdcConsentsBuilder.CONSENTS_KEY), consents.keySet());
        assertEquals(
            Set.of("phs123.c1", "open_access-1000Genomes", "tutorial-biolincc_framingham"), consents.get(BdcConsentsBuilder.CONSENTS_KEY)
        );
    }


    @Test
    public void createConsents_harmonizedConsentsOnly() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of(
            new RasDbgapPermission().setPhsId("phs456").setConsentGroup("c1"),
            new RasDbgapPermission().setPhsId("phs456").setConsentGroup("c2")
        );
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(Set.of(BdcConsentsBuilder.CONSENTS_KEY, BdcConsentsBuilder.HARMONIZED_CONSENTS_KEY), consents.keySet());
        assertEquals(
            Set.of("phs456.c1", "phs456.c2", "open_access-1000Genomes", "tutorial-biolincc_framingham"),
            consents.get(BdcConsentsBuilder.CONSENTS_KEY)
        );
        assertEquals(Set.of("phs456.c1", "phs456.c2"), consents.get(BdcConsentsBuilder.HARMONIZED_CONSENTS_KEY));
    }

    @Test
    public void createConsents_multipleNormalAndHarmonizedConsents() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of(
            new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c1"),
            new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c2"),
            new RasDbgapPermission().setPhsId("phs456").setConsentGroup("c1")
        );
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(Set.of(BdcConsentsBuilder.CONSENTS_KEY, BdcConsentsBuilder.HARMONIZED_CONSENTS_KEY), consents.keySet());
        assertEquals(
            Set.of("phs123.c1", "phs123.c2", "phs456.c1", "open_access-1000Genomes", "tutorial-biolincc_framingham"),
            consents.get(BdcConsentsBuilder.CONSENTS_KEY)
        );
        assertEquals(Set.of("phs456.c1"), consents.get(BdcConsentsBuilder.HARMONIZED_CONSENTS_KEY));
    }


    @Test
    public void createConsents_genomicConsentsOnly() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of(
            new RasDbgapPermission().setPhsId("phs789").setConsentGroup("c1"),
            new RasDbgapPermission().setPhsId("phs789").setConsentGroup("c2")
        );
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(Set.of(BdcConsentsBuilder.CONSENTS_KEY, BdcConsentsBuilder.TOPMED_CONSENTS_KEY), consents.keySet());
        assertEquals(
            Set.of("phs789.c1", "phs789.c2", "open_access-1000Genomes", "tutorial-biolincc_framingham"),
            consents.get(BdcConsentsBuilder.CONSENTS_KEY)
        );
        assertEquals(Set.of("phs789.c1", "phs789.c2"), consents.get(BdcConsentsBuilder.TOPMED_CONSENTS_KEY));
    }

    @Test
    public void createConsents_multipleNormalAndGenomicConsents() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of(
            new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c1"),
            new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c2"),
            new RasDbgapPermission().setPhsId("phs789").setConsentGroup("c1")
        );
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(Set.of(BdcConsentsBuilder.CONSENTS_KEY, BdcConsentsBuilder.TOPMED_CONSENTS_KEY), consents.keySet());
        assertEquals(
            Set.of("phs123.c1", "phs123.c2", "phs789.c1", "open_access-1000Genomes", "tutorial-biolincc_framingham"),
            consents.get(BdcConsentsBuilder.CONSENTS_KEY)
        );
        assertEquals(Set.of("phs789.c1"), consents.get(BdcConsentsBuilder.TOPMED_CONSENTS_KEY));
    }

    @Test
    public void createConsents_harmonizedGenomicConsentsOnly() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of(
            new RasDbgapPermission().setPhsId("phs999").setConsentGroup("c1"),
            new RasDbgapPermission().setPhsId("phs999").setConsentGroup("c2")
        );
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(
            Set.of(BdcConsentsBuilder.CONSENTS_KEY, BdcConsentsBuilder.TOPMED_CONSENTS_KEY, BdcConsentsBuilder.HARMONIZED_CONSENTS_KEY),
            consents.keySet()
        );
        assertEquals(
            Set.of("phs999.c1", "phs999.c2", "open_access-1000Genomes", "tutorial-biolincc_framingham"),
            consents.get(BdcConsentsBuilder.CONSENTS_KEY)
        );
        assertEquals(Set.of("phs999.c1", "phs999.c2"), consents.get(BdcConsentsBuilder.TOPMED_CONSENTS_KEY));
        assertEquals(Set.of("phs999.c1", "phs999.c2"), consents.get(BdcConsentsBuilder.HARMONIZED_CONSENTS_KEY));
    }

    @Test
    public void createConsents_multipleNormalAndHarmonizedGenomicConsents() {
        Set<RasDbgapPermission> dbgapPermissions = Set.of(
            new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c1"),
            new RasDbgapPermission().setPhsId("phs123").setConsentGroup("c2"),
            new RasDbgapPermission().setPhsId("phs999").setConsentGroup("c1")
        );
        Map<String, Set<String>> consents = new BdcConsentsBuilder(DEFAULT_FENCE_MAPPING, dbgapPermissions).createConsents();
        assertEquals(
            Set.of(BdcConsentsBuilder.CONSENTS_KEY, BdcConsentsBuilder.TOPMED_CONSENTS_KEY, BdcConsentsBuilder.HARMONIZED_CONSENTS_KEY),
            consents.keySet()
        );
        assertEquals(
            Set.of("phs123.c1", "phs123.c2", "phs999.c1", "open_access-1000Genomes", "tutorial-biolincc_framingham"),
            consents.get(BdcConsentsBuilder.CONSENTS_KEY)
        );
        assertEquals(Set.of("phs999.c1"), consents.get(BdcConsentsBuilder.TOPMED_CONSENTS_KEY));
        assertEquals(Set.of("phs999.c1"), consents.get(BdcConsentsBuilder.HARMONIZED_CONSENTS_KEY));
    }
}
