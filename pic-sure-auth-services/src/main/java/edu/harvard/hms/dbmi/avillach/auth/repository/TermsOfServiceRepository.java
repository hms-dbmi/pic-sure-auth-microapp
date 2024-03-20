package edu.harvard.hms.dbmi.avillach.auth.repository;

import edu.harvard.dbmi.avillach.data.repository.BaseRepository;
import edu.harvard.hms.dbmi.avillach.auth.entity.TermsOfService;
import org.springframework.stereotype.Repository;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.util.UUID;

/**
 * <p>Provides operations for the TermsOfService  entity to interact with a database.</p>
 * @see TermsOfService
 */
@Repository
public class TermsOfServiceRepository extends BaseRepository<TermsOfService, UUID> {

    protected TermsOfServiceRepository() {
        super(TermsOfService.class);
    }

    public TermsOfService getLatest(){
        CriteriaQuery<TermsOfService> query = cb().createQuery(TermsOfService.class);
        Root<TermsOfService> queryRoot = query.from(TermsOfService.class);
        query.select(queryRoot);
        CriteriaBuilder cb = cb();
        return em.createQuery(query
                .orderBy(cb.desc(queryRoot.get("dateUpdated"))))
                .setMaxResults(1)
                .getSingleResult();
    }
}
