package edu.harvard.iq.dataverse.authorization.groups.impl.ipaddress;

import edu.harvard.iq.dataverse.authorization.groups.GroupProvider;
import edu.harvard.iq.dataverse.authorization.groups.impl.PersistedGlobalGroup;
import edu.harvard.iq.dataverse.authorization.groups.impl.ipaddress.ip.IPv4Address;
import edu.harvard.iq.dataverse.authorization.groups.impl.ipaddress.ip.IPv4Range;
import edu.harvard.iq.dataverse.authorization.groups.impl.ipaddress.ip.IPv6Range;
import edu.harvard.iq.dataverse.authorization.groups.impl.ipaddress.ip.IpAddress;
import edu.harvard.iq.dataverse.authorization.groups.impl.ipaddress.ip.IpAddressRange;
import edu.harvard.iq.dataverse.engine.command.DataverseRequest;
import java.util.HashSet;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Transient;

@NamedQueries({
    @NamedQuery(name="IpGroup.findAll",
               query="SELECT g FROM IpGroup g"),
    @NamedQuery(name="IpGroup.findByPersistedGroupAlias",
               query="SELECT g FROM IpGroup g WHERE g.persistedGroupAlias=:persistedGroupAlias")
})
@Entity
public class IpGroup extends PersistedGlobalGroup {
    
    @OneToMany(mappedBy = "owner", cascade=CascadeType.ALL)
    private Set<IPv6Range> ipv6Ranges;

    @OneToMany(mappedBy = "owner", cascade=CascadeType.ALL)
    private Set<IPv4Range> ipv4Ranges;
    
    @Transient
    private IpGroupProvider provider;
    
    public IpGroup() {
        
    }
    
    public IpGroup(IpGroupProvider provider) {
        this.provider = provider;
    }
    
    @Override
    public boolean contains(DataverseRequest rq) {
        IpAddress addr = rq.getSourceAddress();
        for ( IpAddressRange r : ((addr instanceof IPv4Address) ? ipv4Ranges : ipv6Ranges) ) {
           Boolean containment =  r.contains(addr);
           if ( (containment != null) && containment ) {
               return true;
           }
               
        }
        return false;
    }
    
    public <T extends IpAddressRange> T add( T range ) {
        if ( ipv4Ranges==null ) ipv4Ranges = new HashSet<>();
        if ( ipv6Ranges==null ) ipv6Ranges = new HashSet<>();
        
        range.setOwner(this);
        if ( range instanceof IPv4Range ) {
            ipv4Ranges.add((IPv4Range) range);
        } else {
            ipv6Ranges.add((IPv6Range) range);
        }
        return range;
    }
    
    @SuppressWarnings("element-type-mismatch")
    public void remove( IpAddressRange range ) {
        ( (range instanceof IPv4Range) ? ipv4Ranges : ipv6Ranges ).remove(range);
    }
    
    @Override
    public boolean isEditable() {
        return true;
    }
    
    public void setProvider( IpGroupProvider prv ) {
        provider = prv;
    }

    /**
     * Returns a <strong>read only</strong> set of all the ranges  in the group,
     * both IPv6 and IPv4.
     * @return 
     */
    public Set<IpAddressRange> getRanges() {
        Set<IpAddressRange> ranges = new HashSet<>();
        ranges.addAll( getIpv4Ranges() );
        ranges.addAll( getIpv6Ranges() );
        return ranges;
    }
    
    @Override
    public GroupProvider getGroupProvider() {
        return provider;
    }

    /**
     * Low-level JPA accessor
     * @return 
     * @see #getRanges() 
     */
    public Set<IPv6Range> getIpv6Ranges() {
        return ipv6Ranges;
    }

    /**
     * Low-level JPA accessor
     * @param ipv6Ranges 
     */
    public void setIpv6Ranges(Set<IPv6Range> ipv6Ranges) {
        this.ipv6Ranges = ipv6Ranges;
    }
    /**
     * Low-level JPA accessor
     * @return 
     * @see #getRanges() 
     */
    public Set<IPv4Range> getIpv4Ranges() {
        return ipv4Ranges;
    }

    public void setIpv4Ranges(Set<IPv4Range> ipv4Ranges) {
        this.ipv4Ranges = ipv4Ranges;
    }

    @Override
    public String getSortByString() {
        return this.getDisplayName();
    }

}
