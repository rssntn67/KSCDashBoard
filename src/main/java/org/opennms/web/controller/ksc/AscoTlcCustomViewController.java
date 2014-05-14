//
// This file is part of the OpenNMS(R) Application.
//
// OpenNMS(R) is Copyright (C) 2006-2008 The OpenNMS Group, Inc.  All rights reserved.
// OpenNMS(R) is a derivative work, containing both original code, included code and modified
// code that was published under the GNU General Public License. Copyrights for modified
// and included code are below.
//
// OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
//
// Modifications:
//
// 2010 Feb 10: Catch exception when referenced resource's parent node is missing.
//              Addresses bug 3535. - jeffg@opennms.org
// 2009 Jan 26: Modified handleRequestInternal - part of ksc performance improvement. - ayres@opennms.org
// 2008 Oct 22: Lots of cleanup.  - dj@opennms.org
// 2008 Sep 28: Handle XSS security issues. - ranger@opennms.org
// 2008 Feb 03: Use Asserts in afterPropertiesSet() and setDefaultGraphsPerLine().
//              Use new getReportByIndex method on the KSC factory. - dj@opennms.org
//
// Original code base Copyright (C) 1999-2001 Oculan Corp.  All rights reserved.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
// For more information contact:
//      OpenNMS Licensing       <license@opennms.org>
//      http://www.opennms.org/
//      http://www.opennms.com/
//
package org.opennms.web.controller.ksc;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.hibernate.criterion.MatchMode;
import org.hibernate.criterion.Restrictions;
import org.opennms.core.utils.ThreadCategory;
import org.opennms.netmgt.config.KSC_PerformanceReportFactory;
import org.opennms.netmgt.config.KscReportEditor;
import org.opennms.netmgt.config.kscReports.Graph;
import org.opennms.netmgt.config.kscReports.Report;
import org.opennms.netmgt.dao.SnmpInterfaceDao;
import org.opennms.netmgt.model.OnmsCriteria;
import org.opennms.netmgt.model.OnmsResource;
import org.opennms.netmgt.model.OnmsSnmpInterface;
import org.opennms.netmgt.model.PrefabGraph;
import org.opennms.web.WebSecurityUtils;
import org.opennms.web.graph.KscResultSet;
import org.opennms.web.svclayer.KscReportService;
import org.opennms.web.svclayer.ResourceService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.ObjectRetrievalFailureException;
import org.springframework.util.Assert;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;

/**
 * <p>CustomViewController class.</p>
 *
 * @author ranger
 * @version $Id: $
 * @since 1.8.1
 */
public class AscoTlcCustomViewController extends AbstractController implements InitializingBean {

    private final String DEFAULT_GRAPH_TYPE = "mib2.HCbits";
    private final String OPT_GRAPH_TYPE = "mib2.bits";
    
    private final String DEFAULT_TIME_SPAN  = "7_day";
    
    public enum Parameters {
        timespan,
        graphtype
    }

    private KSC_PerformanceReportFactory m_kscReportFactory;
    private KscReportService m_kscReportService;
    private ResourceService m_resourceService;
    private int m_defaultGraphsPerLine = 0;
    private Executor m_executor;
    
    @Autowired
    private SnmpInterfaceDao m_snmpInterfaceDao;
    
    private Set<String> m_resourcesPendingPromotion = Collections.synchronizedSet(new HashSet<String>());

    /** {@inheritDoc} */
    @Override
    protected ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
      
        // Get Form Variable
        String username = request.getRemoteUser();
        if (username == null)
            throw new ServletException("Username is null: must be authenticated");
        
        Integer reportId = getReportId(username);
        if (reportId == null) {
            System.out.println("AscoTlc: DEBUG no KSC report found for username: "+username);

            KscReportEditor editor = KscReportEditor.getFromSession(request.getSession(), false);
            editor.loadNewWorkingReport();
            Report newreport = editor.getWorkingReport();
            newreport.setTitle(username);
            newreport.setShow_graphtype_button(false);
            newreport.setGraphs_per_line(getDefaultGraphsPerLine());
            newreport.setShow_timespan_button(true);
            System.out.println("AscoTlc: DEBUG creating new KSC report for username: "+username);

            List<String> resources = new ArrayList<String>();

            OnmsCriteria criteria = new OnmsCriteria(OnmsSnmpInterface.class);
            criteria.add(Restrictions.ilike("ifAlias", username, MatchMode.ANYWHERE));
            for (OnmsSnmpInterface snmpiface: m_snmpInterfaceDao.findMatching(criteria)){
                String resourceId = "node["+snmpiface.getNode().getNodeId()+"].interfaceSnmp["+snmpiface.computeLabelForRRD()+"]";
                System.out.println("AscoTlc: DEBUG snmpinterface ifalias match found: resourceId:"+resourceId);
                resources.add(resourceId);
            }
                        
            for ( String resourceId: resources) {
                System.out.println("AscoTlc: DEBUG try to add graph for resource: "+resourceId);
                Graph vGraph = new Graph();
                vGraph.setTitle("");
                vGraph.setResourceId(resourceId);
                vGraph.setTimespan(DEFAULT_TIME_SPAN);
            
// Check the resource
                OnmsResource resource = getResourceService().getResourceById(resourceId);

                if (resource == null) {
                    System.out.println("AscoTlc: DEBUG no active resource found: skipping");
                    continue;
                } else {
                    System.out.println("AscoTlc: DEBUG adding graphs for active resource: "+resource.getId());
                }
                PrefabGraph[] prefab_graphs = getResourceService().findPrefabGraphsForResource(resource);
                for (PrefabGraph pg: prefab_graphs) {
                    
                    if (OPT_GRAPH_TYPE.equals(pg.getName())) { 
                        vGraph.setGraphtype(OPT_GRAPH_TYPE);
                        break;
                    } else if (DEFAULT_GRAPH_TYPE.equals(pg.getName())) {
                        vGraph.setGraphtype(DEFAULT_GRAPH_TYPE);
                        break;
                    }
                }
                
                if (vGraph.getGraphtype() != null) {
                    System.out.println("AscoTlc: DEBUG adding graph: "+vGraph.getResourceId());
                    System.out.println("AscoTlc: DEBUG adding graph: "+vGraph.getGraphtype());
                    newreport.addGraph(vGraph);                   
                } else {
                    System.out.println("AscoTlc: DEBUG no default graph found: skipping resource: "+ resourceId);                    
                }
            }            
            System.out.println("AscoTlc: DEBUG saving KSC report for username: "+username);
            editor.unloadWorkingReport(getKscReportFactory());
            // Save the changes to the config file
            getKscReportFactory().saveCurrent();
            
            reportId = getReportId(username);
            if (reportId == null)
                throw new ServletException("Report could not be found in config file for username: '" + username + "'");                
        }

        String overrideTimespan = WebSecurityUtils.sanitizeString(request.getParameter(Parameters.timespan.toString()));
        if ("null".equals(overrideTimespan) || "none".equals(overrideTimespan)) {
            overrideTimespan = null;
        }

        String overrideGraphType = WebSecurityUtils.sanitizeString(request.getParameter(Parameters.graphtype.toString()));
        if ("null".equals(overrideGraphType) || "none".equals(overrideGraphType)) {
            overrideGraphType = null;
        }
      
        // Load report to view 
        Report report = m_kscReportFactory.getReportByIndex(reportId);
        if (report == null) {
            
            throw new ServletException("Report could not be found in config file for index '" + reportId + "'");
        }
  
        // Get the list of available prefabricated graph options 
        Map<String, OnmsResource> resourceMap = new HashMap<String, OnmsResource>();
        Set<PrefabGraph> prefabGraphs = new TreeSet<PrefabGraph>();
        removeBrokenGraphsFromReport(report);
        List<Graph> graphCollection = report.getGraphCollection();
        if (!graphCollection.isEmpty()) {
            List<OnmsResource> resources = getKscReportService().getResourcesFromGraphs(graphCollection);
            for (int i = 0; i < graphCollection.size(); i++) {
                Graph graph = graphCollection.get(i);
                OnmsResource resource = null;
                try {
                    resource = resources.get(i);
                }catch(IndexOutOfBoundsException e) {
                    log().debug("Resource List Index Out Of Bounds Caught ", e);
                }
                
                resourceMap.put(graph.toString(), resource);
                if (resource == null) {
                    log().debug("Could not get resource for graph " + graph + " in report " + report.getTitle());
                } else {
                    prefabGraphs.addAll(Arrays.asList(getResourceService().findPrefabGraphsForResource(resource)));
                }
                
                
            }
      
            // Get default graph type from first element of graph_options
            // XXX Do we care about the tests on reportType?
        }
        
        List<KscResultSet> resultSets = new ArrayList<KscResultSet>(report.getGraphCount());
        for (Graph graph : graphCollection) {
            OnmsResource resource = resourceMap.get(graph.toString());
            if (resource != null) {
                promoteResourceAttributesIfNecessary(resource);
            }

            String displayGraphType;
            if (overrideGraphType == null) {
                displayGraphType = graph.getGraphtype();
            } else {
                displayGraphType = overrideGraphType;
            }
            
            PrefabGraph displayGraph;
            try {
                displayGraph = getResourceService().getPrefabGraph(displayGraphType);
            } catch (ObjectRetrievalFailureException e) {
                if (log().isDebugEnabled()) {
                    log().debug("The prefabricated graph '" + displayGraphType + "' does not exist: " + e, e);
                }
                displayGraph = null;
            }
            
            boolean foundGraph = false;
            if (resource != null) {
                for (PrefabGraph availableGraph : getResourceService().findPrefabGraphsForResource(resource)) {
                    if (availableGraph.equals(displayGraph)) {
                        foundGraph = true;
                        break;
                    }
                }
            }
            
            if (!foundGraph) {
                displayGraph = null;
            }
            
            // gather start/stop time information
            String displayTimespan = null;
            if (overrideTimespan == null) {
                displayTimespan = graph.getTimespan();
            } else {
                displayTimespan = overrideTimespan;
            }
            Calendar beginTime = Calendar.getInstance();
            Calendar endTime = Calendar.getInstance();
            KSC_PerformanceReportFactory.getBeginEndTime(displayTimespan, beginTime, endTime);
            
            KscResultSet resultSet = new KscResultSet(graph.getTitle(), beginTime.getTime(), endTime.getTime(), resource, displayGraph);
            resultSets.add(resultSet);
        }
        
        ModelAndView modelAndView = new ModelAndView("/dashboard/ascoTlcCustomView");

        modelAndView.addObject("loggedIn", request.getRemoteUser() != null);
        if (report != null) {
            modelAndView.addObject("report", username);
        }
        
        modelAndView.addObject("title", report.getTitle());
        modelAndView.addObject("resultSets", resultSets);
        
        if (report.getShow_timespan_button()) {
            if (overrideTimespan == null || !getKscReportService().getTimeSpans(true).containsKey(overrideTimespan)) {
                modelAndView.addObject("timeSpan", "none");
            } else {
                modelAndView.addObject("timeSpan", overrideTimespan);
            }
            modelAndView.addObject("timeSpans", getKscReportService().getTimeSpans(true));
        } else {
            // Make sure it's null so the pulldown list isn't shown
            modelAndView.addObject("timeSpan", null);
        }

        if (report.getShow_graphtype_button()) {
            LinkedHashMap<String, String> graphTypes = new LinkedHashMap<String, String>();
            graphTypes.put("none", "none");
            for (PrefabGraph graphOption : prefabGraphs) {
                graphTypes.put(graphOption.getName(), graphOption.getName());
            }
            
            if (overrideGraphType == null || !graphTypes.containsKey(overrideGraphType)) {
                modelAndView.addObject("graphType", "none");
            } else {
                modelAndView.addObject("graphType", overrideGraphType);
            }
            modelAndView.addObject("graphTypes", graphTypes);
        } else {
            // Make sure it's null so the pulldown list isn't shown
            modelAndView.addObject("graphType", null);
        }
        
        modelAndView.addObject("showCustomizeButton", false);

        if (report.getGraphs_per_line() > 0) {
            modelAndView.addObject("graphsPerLine", report.getGraphs_per_line());
        } else {
            modelAndView.addObject("graphsPerLine", getDefaultGraphsPerLine());
        }
        
        return modelAndView;
    }
    
    
    private Integer getReportId(String username) {
        for (Integer reportId: getKscReportService().getReportList().keySet() ) {
            if (getKscReportService().getReportList().get(reportId).equals(username))
                return reportId;
        }
        return null;
    }
    
    private void removeBrokenGraphsFromReport(Report report) {
        for (Iterator<Graph> itr = report.getGraphCollection().iterator(); itr.hasNext();) {
            Graph graph = itr.next();
            try {
                getKscReportService().getResourceFromGraph(graph);
            } catch (ObjectRetrievalFailureException orfe) {
                log().error("Removing graph '" + graph.getTitle() + "' in KSC report '" + report.getTitle() + "' because the resource it refers to could not be found. Perhaps resource '"+ graph.getResourceId() + "' (or its ancestor) referenced by this graph no longer exists?");
                itr.remove();
            } catch (Throwable e) {
                log().error("Unexpected error while scanning through graphs in report: " + e.getMessage(), e);
                itr.remove();
            }
        }
    }

    private void promoteResourceAttributesIfNecessary(final OnmsResource resource) {
        boolean needToSchedule = false;
        if(resource != null && resource.getId() != null) {
            needToSchedule = m_resourcesPendingPromotion.add(resource.getId());
        }
        if (needToSchedule) {
            m_executor.execute(new Runnable() {

                public void run() {
                        getResourceService().promoteGraphAttributesForResource(resource);
                        m_resourcesPendingPromotion.remove(resource.getId());
                }
                
            });
        }
        
    }

    private static ThreadCategory log() {
        return ThreadCategory.getInstance(AscoTlcCustomViewController.class);
    }

    /**
     * <p>getKscReportFactory</p>
     *
     * @return a {@link org.opennms.netmgt.config.KSC_PerformanceReportFactory} object.
     */
    public KSC_PerformanceReportFactory getKscReportFactory() {
        return m_kscReportFactory;
    }

    /**
     * <p>setKscReportFactory</p>
     *
     * @param kscReportFactory a {@link org.opennms.netmgt.config.KSC_PerformanceReportFactory} object.
     */
    public void setKscReportFactory(KSC_PerformanceReportFactory kscReportFactory) {
        m_kscReportFactory = kscReportFactory;
    }

    /**
     * <p>getDefaultGraphsPerLine</p>
     *
     * @return a int.
     */
    public int getDefaultGraphsPerLine() {
        return m_defaultGraphsPerLine;
    }

    /**
     * <p>setDefaultGraphsPerLine</p>
     *
     * @param defaultGraphsPerLine a int.
     */
    public void setDefaultGraphsPerLine(int defaultGraphsPerLine) {
        Assert.isTrue(defaultGraphsPerLine > 0, "property defaultGraphsPerLine must be greater than zero");

        m_defaultGraphsPerLine = defaultGraphsPerLine;
    }

    /**
     * <p>getKscReportService</p>
     *
     * @return a {@link org.opennms.web.svclayer.KscReportService} object.
     */
    public KscReportService getKscReportService() {
        return m_kscReportService;
    }

    /**
     * <p>setKscReportService</p>
     *
     * @param kscReportService a {@link org.opennms.web.svclayer.KscReportService} object.
     */
    public void setKscReportService(KscReportService kscReportService) {
        m_kscReportService = kscReportService;
    }

    /**
     * <p>getResourceService</p>
     *
     * @return a {@link org.opennms.web.svclayer.ResourceService} object.
     */
    public ResourceService getResourceService() {
        return m_resourceService;
    }

    /**
     * <p>setResourceService</p>
     *
     * @param resourceService a {@link org.opennms.web.svclayer.ResourceService} object.
     */
    public void setResourceService(ResourceService resourceService) {
        m_resourceService = resourceService;
    }

    /**
     * <p>afterPropertiesSet</p>
     *
     * @throws java.lang.Exception if any.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.state(m_kscReportFactory != null, "property kscReportFactory must be set");
        Assert.state(m_kscReportService != null, "property kscReportService must be set");
        Assert.state(m_resourceService != null, "property resourceService must be set");
        Assert.state(m_defaultGraphsPerLine != 0, "property defaultGraphsPerLine must be set");
        
        m_executor = Executors.newSingleThreadExecutor();
    }

}
