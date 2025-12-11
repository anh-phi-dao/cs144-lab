/******************************************************************************
 * ctcp.c
 * ------
 * Implementation of cTCP done here. This is the only file you need to change.
 * Look at the following files for references and useful functions:
 *   - ctcp.h: Headers for this file.
 *   - ctcp_iinked_list.h: Linked list functions for managing a linked list.
 *   - ctcp_sys.h: Connection-related structs and functions, cTCP segment
 *                 definition.
 *   - ctcp_utils.h: Checksum computation, getting the current time.
 *
 *****************************************************************************/

#include "ctcp.h"
#include "ctcp_linked_list.h"
#include "ctcp_sys.h"
#include "ctcp_utils.h"

#define MAX_SEG_IN_WINDOW MAX_WINDOW *MAX_SEG_DATA_SIZE

#define ENABLE_ACK_BIT 1
#define DISABLE_ACK_BIT 0
#define MAX_ATTEMP_RETRANSMISSION 5

#if USING_PADDING == 1
#define PADDING_SEGMENT
#endif

#define GET_RECEIVE_NUMBER 0
#define GET_SEND_NUMBER 1

#define NORMAL_STATE 0
#define FIN_SENT_OR_RECEIVED 1

#define DID_NOT_FIND_SEGMENT_IN_BUFFER 0
#define FOUND_SEGMENT_IN_BUFFER 1

#define NO_SEGMENT_NEED_TO_BE_RETRANSMITTED 0
#define THERE_ARE_SEGMENT_REQUIRE_RETRANSMISSION 1

struct ctcp_segment_timer
{
  uint32_t seqno;
  long current_time;
};

/**
 * Connection state.
 *
 * Stores per-connection information such as the current sequence number,
 * unacknowledged packets, etc.
 *
 * You should add to this to store other fields you might need.
 */
struct ctcp_state
{
  struct ctcp_state *next;  /* Next in linked list */
  struct ctcp_state **prev; /* Prev in linked list */

  conn_t *conn;            /* Connection object -- needed in order to figure
                              out destination when sending */
  linked_list_t *segments; /* Linked list of segments sent to this connection.
                              It may be useful to have multiple linked lists
                              for unacknowledged segments, segments that
                              haven't been sent, etc. Lab 1 uses the
                              stop-and-wait protocol and therefore does not
                              necessarily need a linked list. You may remove
                              this if this is the case for you */

  /* FIXME: Add other needed fields. */
  // linked_list_t *timer;            /*store the timer value*/
  linked_list_t *receive_segments; /*Linked list of received segments*/
  linked_list_t *timer;
  ctcp_config_t *cfg; /*connection configuration (RT timeout,transmission time,receive window, send window)*/
  uint32_t nextseqno;
  uint32_t send_base;
  uint32_t receive_base;
  uint32_t num_of_received_failed_ack;
  uint32_t num_of_retransmission; /* number of retransmission*/
  uint8_t FIN_Close;
};

/**
 * Linked list of connection states. Go through this in ctcp_timer() to
 * resubmit segments and tear down connections.
 */
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
          code! Helper functions make the code clearer and cleaner. */
char buff[MAX_SEG_DATA_SIZE + 1];
long track_time;

ctcp_state_t *ctcp_init(conn_t *conn, ctcp_config_t *cfg)
{
  /* Connection could not be established. */
  if (conn == NULL)
  {
    return NULL;
  }

  /* Established a connection. Create a new state and update the linked list
     of connection states. */
  ctcp_state_t *state = calloc(sizeof(ctcp_state_t), 1);
  state->next = state_list;
  state->prev = &state_list;
  if (state_list)
    state_list->prev = &state->next;
  state_list = state;

  /* Set fields. */
  state->conn = conn;
  /* FIXME: Do any other initialization here. */
  state->segments = ll_create();
  state->receive_segments = ll_create();
  state->timer = ll_create();

  state->nextseqno = 1;
  state->send_base = 1;
  state->receive_base = 1;

  cfg->recv_window = MAX_SEG_IN_WINDOW;
  cfg->send_window = MAX_SEG_IN_WINDOW;

  cfg->rt_timeout = 500;
  cfg->timer = 3000;

  state->cfg = malloc(sizeof(ctcp_config_t));
  memcpy(state->cfg, cfg, sizeof(ctcp_config_t));
  state->num_of_received_failed_ack = 0;
  state->num_of_retransmission = 0;
  return state;
}

void clean_all_object_int_linked_list(linked_list_t *segments)
{
  ll_node_t *track = segments->head;

  while (track != NULL)
  {
    if (track->object != NULL)
    {
      free(track->object);
      track->object = NULL;
    }
    track = track->next;
  }
}

/**
 * @brief create segment for TCP connection
 * @param state: State of all connection
 * @param current_segment: Pointer to received segment, if sender just want to send a packet, then this param is NULL
 * @param buff: pointer to data packets
 * @param with_ACK: =0 -> Normal packets, =1 -> receiver want to send acknowledgement back to sender
 * @return a complete segment
 */
ctcp_segment_t *create_segment(ctcp_state_t *state, ctcp_segment_t *current_segment, const char *buff, size_t len, uint8_t with_ACK)
{

  ctcp_segment_t *tcp_segment;
  size_t len_for_segment;
#ifdef PADDING_SEGMENT
  uint8_t padd = (sizeof(ctcp_segment_t) + len) % 4;
  if (padd > 0)
  {
    len_for_segment = sizeof(ctcp_segment_t) + len + 4 - padd;
  }
  else
  {
    len_for_segment = sizeof(ctcp_segment_t) + len;
  }
#else
  len_for_segment = sizeof(ctcp_segment_t) + len;
#endif
  tcp_segment = malloc(len_for_segment);
  memset(tcp_segment, 0, len_for_segment);
  if (buff != NULL && len != 0)
  {
    memset(tcp_segment->data, 0, len_for_segment - sizeof(ctcp_segment_t));
    memcpy(tcp_segment->data, buff, len);
  }
  if (current_segment != NULL)
  {
    uint32_t current_data_len = current_segment->len - sizeof(ctcp_segment_t);
    tcp_segment->ackno = (current_segment->seqno) + current_data_len;
    tcp_segment->seqno = current_segment->ackno;
  }
  else
  {
    tcp_segment->ackno = 1;
    tcp_segment->seqno = state->nextseqno;
  }
  tcp_segment->len = len_for_segment;
  tcp_segment->window = MAX_SEG_DATA_SIZE;
  tcp_segment->flags = 0;
  if (with_ACK == ENABLE_ACK_BIT)
  {
    tcp_segment->flags |= ACK;
  }
  tcp_segment->cksum = 0;
  tcp_segment->cksum = cksum(tcp_segment, tcp_segment->len);
  return tcp_segment;
}

ctcp_segment_timer_t *create_timer_for_segment(ctcp_segment_t *current_segment)
{
  ctcp_segment_timer_t *time = malloc(sizeof(ctcp_segment_timer_t));
  time->current_time = current_time();
  time->seqno = current_segment->seqno;
  return time;
}

ctcp_segment_t *create_FIN(ctcp_state_t *state)
{
  ctcp_segment_t *tcp_segment = malloc(sizeof(ctcp_segment_t));
  tcp_segment->flags = 0;
  tcp_segment->flags |= FIN;
  tcp_segment->len = sizeof(ctcp_segment_t);
  tcp_segment->window = MAX_SEG_DATA_SIZE;
  tcp_segment->ackno = 1;
  tcp_segment->seqno = state->nextseqno;
  tcp_segment->cksum = 0;
  tcp_segment->cksum = cksum(tcp_segment, tcp_segment->len);
  return tcp_segment;
}

ctcp_segment_t *free_ctcp_segment_t(ctcp_segment_t *segment)
{
  if (segment != NULL)
  {
    free(segment);
    segment = NULL;
  }
  return segment;
}

void segment_host_to_network(ctcp_segment_t *segment)
{
  segment->ackno = htonl(segment->ackno);
  segment->seqno = htonl(segment->seqno);
  segment->len = htons(segment->len);
  segment->window = htons(segment->window);
  segment->flags = htonl(segment->flags);
}

void segment_network_to_host(ctcp_segment_t *segment)
{
  segment->ackno = ntohl(segment->ackno);
  segment->seqno = ntohl(segment->seqno);
  segment->len = ntohs(segment->len);
  segment->window = ntohs(segment->window);
  segment->flags = ntohl(segment->flags);
}

void ctcp_destroy(ctcp_state_t *state)
{
  /* Update linked list. */
  if (state->next)
    state->next->prev = state->prev;

  *state->prev = state->next;
  conn_remove(state->conn);

  /* FIXME: Do any other cleanup here. */

  clean_all_object_int_linked_list(state->segments);
  ll_destroy(state->segments);
  state->segments = NULL;

  clean_all_object_int_linked_list(state->receive_segments);
  ll_destroy(state->receive_segments);
  state->receive_segments = NULL;

  clean_all_object_int_linked_list(state->timer);
  ll_destroy(state->timer);
  state->timer = NULL;

  free(state->cfg);
  state->cfg = NULL;

  free(state);
  end_client();
}

void print_state_number(ctcp_state_t *state)
{
  fprintf(stderr, "[INFO] nextseqnumber number: %d\n", state->nextseqno);
  fprintf(stderr, "[INFO] send base: %d\n", state->send_base);
  fprintf(stderr, "[INFO] receive base: %d\n", state->receive_base);
}

void send_FIN(ctcp_state_t *state)
{
  ctcp_segment_t *fin_seg = create_FIN(state);
  uint16_t seg_len = fin_seg->len;
  segment_host_to_network(fin_seg);
#ifdef DEBUG_SEGMENT
  print_hdr_ctcp(fin_seg);
#endif
  conn_send(state->conn, fin_seg, seg_len);
  fin_seg = free_ctcp_segment_t(fin_seg);
  /*destroy the state*/
  memset(buff, 0, sizeof(buff));
  conn_output(state->conn, buff, 0);
#ifdef PRINT_FINAL_STATE
  print_state_number(state);
#endif
}

void update_send_base(ctcp_state_t *state)
{
  ll_node_t *track = state->segments->head;

  while (track != NULL)
  {
    ctcp_segment_t *seg = (ctcp_segment_t *)track->object;

    if (seg->seqno == state->send_base)
    {
      /*when meet an acked segment*/
      if (seg->ackno == seg->seqno + seg->len - sizeof(ctcp_segment_t))
      {
        delete_timer(state, seg->seqno);
        state->send_base = seg->seqno + seg->len - sizeof(ctcp_segment_t);
        ll_node_t *temp = track;
        track = track->next;
        ll_remove(state->segments, temp);
        free(temp->object);
        continue;
      }
      else
      {
        break;
      }
    }
    track = track->next;
  }
}

void send_acknowledgement_of_received_packet(ctcp_state_t *state, ctcp_segment_t *segment)
{
  ctcp_segment_t *sent_seg = create_segment(state, segment, NULL, 0, ENABLE_ACK_BIT);
  uint16_t len = sent_seg->len;
  segment_host_to_network(sent_seg);
  conn_send(state->conn, sent_seg, len);
#ifdef DEBUG_SEGMENT
  fprintf(stderr, "[INFO] Receiver send acknowledgement");
  print_hdr_ctcp(sent_seg);
#endif
  sent_seg = free_ctcp_segment_t(sent_seg);
}

uint32_t find_segment_in_buffer(linked_list_t *buff, ctcp_segment_t *segment)
{
  ll_node_t *track = buff->head;
  while (track != NULL)
  {
    ctcp_segment_t *buff_seg = (ctcp_segment_t *)track->object;
    if (segment->seqno == buff_seg->seqno)
    {
      return FOUND_SEGMENT_IN_BUFFER;
    }
    track = track->next;
  }
  return DID_NOT_FIND_SEGMENT_IN_BUFFER;
}

ctcp_segment_timer_t *find_timer(ctcp_state_t *state, uint32_t seqno)
{
  ll_node_t *track = state->timer->head;
  while (track != NULL)
  {
    ctcp_segment_timer_t *timer = (ctcp_segment_timer_t *)track->object;
    if (timer->seqno == seqno)
    {
      return timer;
    }
    track = track->next;
  }
  return NULL;
}

void delete_timer(ctcp_state_t *state, uint32_t seqno)
{
  ll_node_t *track = state->timer->head;
  while (track != NULL)
  {
    ctcp_segment_timer_t *timer = (ctcp_segment_timer_t *)track->object;
    if (timer->seqno == seqno)
    {
      free(track->object);
      ll_remove(state->timer, track);
      return;
    }
    track = track->next;
  }
}

void retransmit_segments(ctcp_state_t *state)
{
  ll_node_t *track = state->segments->head;
  uint8_t require_transmit = NO_SEGMENT_NEED_TO_BE_RETRANSMITTED;
  while (track != NULL)
  {
    ctcp_segment_t *seg = (ctcp_segment_t *)track->object;
    if (seg->ackno == 1)
    {
      ctcp_segment_timer_t *time = find_timer(state, seg->seqno);
      if (time == NULL)
      {
#ifdef DEBUG_RETRANSMISSION
        fprintf(stderr, "Can not find timer for unacknowledge segment with seqno %d\n", seg->seqno);
#endif
        track = track->next;
        continue;
      }
      long delta_time = current_time() - time->current_time;
      if (delta_time < state->cfg->rt_timeout)
      {
#ifdef DEBUG_RETRANSMISSION
        fprintf(stderr, "Can not find timer for unacknowledge segment with seqno %d\n", seg->seqno);
#endif
        track = track->next;
        continue;
      }
      require_transmit = THERE_ARE_SEGMENT_REQUIRE_RETRANSMISSION;
      time->current_time = current_time();
      memset(buff, 0, sizeof(buff));
      uint32_t new_seqno = seg->seqno + (seg->len - sizeof(ctcp_segment_t));
      if (seg->seqno >= state->send_base && new_seqno <= (state->send_base + state->cfg->recv_window))
      {
        ctcp_segment_t *sent_seg = malloc(seg->len);
        memset(sent_seg, 0, seg->len);
        memcpy(sent_seg, seg, seg->len);
        segment_host_to_network(sent_seg);
#ifdef DEBUG_SEGMENT
        fprintf(stderr, "[INFO] Sender retransmit");
        print_hdr_ctcp(sent_seg);
#endif
        conn_send(state->conn, sent_seg, seg->len);
        sent_seg = free_ctcp_segment_t(sent_seg);
      }
    }
    track = track->next;
  }
  if (require_transmit == THERE_ARE_SEGMENT_REQUIRE_RETRANSMISSION)
  {
    state->num_of_retransmission++;
  }
}

void add_to_buffer_with_order(linked_list_t *buff, ctcp_segment_t *segment)
{
  ll_node_t *track = buff->head;
  if (track == NULL)
  {
    ll_add(buff, segment);
    return;
  }
  while (track != NULL)
  {
    ctcp_segment_t *buffered_segment = (ctcp_segment_t *)track->object;
    if (segment->seqno > buffered_segment->seqno)
    {
      track = track->next;
    }
    else
    {
      break;
    }
  }
  track = track->prev;
  ll_add_after(buff, track, segment);
}

int is_corrupt(ctcp_segment_t *segment)
{
  uint16_t segment_cksum = segment->cksum;
  segment->cksum = 0;
  int result = cksum(segment, ntohs(segment->len)) != segment_cksum;
  segment->cksum = segment_cksum;
  return result;
}

void ctcp_read(ctcp_state_t *state)
{
  /* FIXME */

  int read_bytes = 0;
  do
  {
    memset(buff, 0, sizeof(buff));
    /*read from associated standard input*/
    read_bytes = conn_input(state->conn, buff, MAX_SEG_DATA_SIZE / 2);
    /*If there are available data, send to receiver and stostate->cur_seqno re in buffer*/
    if (read_bytes > 0)
    {
      /*send to tcp*/
      ctcp_segment_t *sent_segment = create_segment(state, NULL, buff, read_bytes, ENABLE_ACK_BIT);
      ctcp_segment_timer_t *sent_seg_timer = create_timer_for_segment(sent_segment);
      /*store to buffer*/
      uint32_t new_seqno = sent_segment->seqno + sent_segment->len - sizeof(ctcp_segment_t);
      ll_add(state->segments, sent_segment);
      ll_add(state->timer, sent_seg_timer);
      /*check sender window size*/
      if (sent_segment->seqno >= state->send_base && new_seqno <= (state->send_base + state->cfg->recv_window))
      {
        uint16_t seg_len = sent_segment->len;
        /*update for later use of retransmission*/
        ctcp_segment_t *sent_seg = malloc(sent_segment->len);
        memcpy(sent_seg, sent_segment, sent_segment->len);
        segment_host_to_network(sent_seg);
#ifdef DEBUG_SEGMENT
        fprintf(stderr, "[INFO] Sender");
        print_hdr_ctcp(sent_seg);
#endif
        conn_send(state->conn, sent_seg, seg_len);
        sent_seg = free_ctcp_segment_t(sent_seg);
        state->nextseqno = new_seqno;
      }
    }
    /*When it detect an EOF, send a FIN and destroy connection*/
    else if (read_bytes < 0)
    {
      if (state != NULL)
      {
        /*send a FIN*/
        send_FIN(state);
        state->FIN_Close = FIN_SENT_OR_RECEIVED;
        track_time = current_time();
        fprintf(stderr, "[INFO] Write an EOF,sending FIN and closing connection\n");
      }
    }
  } while (read_bytes > 0);
}

void ctcp_receive(ctcp_state_t *state, ctcp_segment_t *segment, size_t len)
{
/* FIXME */
#ifdef DEBUG_RECEIVE
  fprintf(stderr, "[INFO] Receiver");
#endif
#ifdef DEBUG_SEGMENT

  print_hdr_ctcp(segment);
#endif
  segment_network_to_host(segment);
#ifdef DEBUF_SEGMENT_LEN
  fprintf(stderr, "[INFO] Len = %lu and segment->len = %d\n", len, segment->len);
#endif
  if (len < sizeof(ctcp_segment_t))
  {
    free(segment);
    return;
  }
  if (len < segment->len)
  {
    free(segment);
    return;
  }
  uint16_t checksum = cksum(segment, segment->len);
  if (checksum != 0xffff)
  {
    free(segment);
    return;
  }
  /*Receive FIN, output any remain segment, destroy connection*/
  if ((segment->flags & FIN) != 0)
  {
    send_acknowledgement_of_received_packet(state, segment);
    if (state->FIN_Close == NORMAL_STATE)
    {
      send_FIN(state);
      state->FIN_Close = FIN_SENT_OR_RECEIVED;
      track_time = current_time();
      fprintf(stderr, "[INFO] Received FIN, closing connection\n");
    }
    free(segment);
    return;
  }
  else if ((segment->flags & ACK) != 0)
  {
    if (state->FIN_Close == FIN_SENT_OR_RECEIVED)
    {
      free(segment);
      return;
    }
    /*on sender side when receiving acknowledgement*/
    if (segment->len == sizeof(ctcp_segment_t))
    {
      if (segment->ackno <= (state->send_base + state->cfg->send_window))
      {
        ll_node_t *track = state->segments->head;
        while (track != NULL)
        {

          ctcp_segment_t *sender_buff_segment = (ctcp_segment_t *)track->object;
          uint32_t expected_ackno = sender_buff_segment->seqno + sender_buff_segment->len - sizeof(ctcp_segment_t);
          if (expected_ackno == segment->ackno)
          {

#ifdef DEBUG_INCOMING_ACKNOWLEDGEMENT
            fprintf(stderr, "[INFO] Found segment in buffer that corresponding to ack\n");
            fprintf(stderr, "[INFO] segment->ackno=%d buffed_seqno=%d expected_ackno=%d\n", segment->ackno, sender_buff_segment->seqno, expected_ackno);
            fprintf(stderr, "[INFO] state->sendbase=%d\n", state->send_base);
#endif
            /*this will make the segment become acknowledged*/
            /*A segment is acknowledged if its ackno!=1*/
            sender_buff_segment->ackno = segment->ackno;
            update_send_base(state);
            break;
          }
          track = track->next;
        }
      }
    }
    else
    {
      uint32_t next_seqno = segment->seqno + segment->len - sizeof(ctcp_segment_t);
      send_acknowledgement_of_received_packet(state, segment);
      if (segment->seqno >= state->receive_base && next_seqno <= (state->receive_base + state->cfg->send_window))
      {

        if (find_segment_in_buffer(state->receive_segments, segment) == DID_NOT_FIND_SEGMENT_IN_BUFFER)
        {
          /*must add follow order*/
          ctcp_segment_t *segment_should_be_buff = malloc(segment->len);
          memset(segment_should_be_buff, 0, segment->len);
          memcpy(segment_should_be_buff, segment, segment->len);
          add_to_buffer_with_order(state->receive_segments, segment_should_be_buff);
        }
        if (segment->seqno == state->receive_base)
        {
          ctcp_output(state);
        }
      }
    }
  }

#ifdef PRINT_FINAL_STATE
  print_state_number(state);
#endif
}

void ctcp_output(ctcp_state_t *state)
{
  /* FIXME */
  size_t size = conn_bufspace(state->conn);
  ll_node_t *track = state->receive_segments->head;
  if (size > 0)
  {
    while (track != NULL)
    {
      ctcp_segment_t *out_seg = (ctcp_segment_t *)track->object;
      if (track->next == NULL)
      {
        conn_output(state->conn, out_seg->data, out_seg->len - sizeof(ctcp_segment_t));
        state->receive_base = out_seg->seqno + out_seg->len - sizeof(ctcp_segment_t);
        free(track->object);
        ll_remove(state->receive_segments, track);
        break;
      }
      else
      {
        ctcp_segment_t *next_out_seg = (ctcp_segment_t *)track->next->object;
        if (next_out_seg->seqno == (out_seg->seqno + out_seg->len - sizeof(ctcp_segment_t)))
        {
          conn_output(state->conn, out_seg->data, out_seg->len - sizeof(ctcp_segment_t));
          state->receive_base = out_seg->seqno + out_seg->len - sizeof(ctcp_segment_t);
          ll_node_t *temp = track;
          track = track->next;
          free(temp->object);
          ll_remove(state->receive_segments, temp);
        }
        else
        {
          break;
        }
      }
    }
  }
}

void ctcp_timer()
{
  /* FIXME */
  /* FIXME */
  if (state_list == NULL)
  {
    return;
  }
  /*when the number of retransmission is greater than 5, this means that the connection has been destroyed*/
  /*Destroy the connection state*/
  if (state_list->num_of_retransmission >= 10)
  {
#ifdef DEBUG_RETRANSMISSION
    fprintf(stderr, "[ERROR] Too many retransmission, destroying the connection\n");
#endif
    ctcp_destroy(state_list);
    return;
  }
  /*when host send or recieve a FIN, destroy the connection*/
  if (state_list->FIN_Close == FIN_SENT_OR_RECEIVED)
  {

    if ((current_time() - track_time) > 5000)
    {
#ifdef DEBUG_FIN_SIGNAL
      fprintf(stderr, "[INFO] Connection has been destroyed due to FIN signal\n");
#endif
      ctcp_destroy(state_list);
    }
    return;
  }

  /*When sender transmit,seqno=cur_seqno */
  /*If after amount of time, state->seqno=seqno,this means that the segments has not been successfully transmitted*/
  /*Retransmit the segment*/
  ll_node_t *track = state_list->segments->head;

  if (track != NULL)
  {
    retransmit_segments(state_list);
  }
  else
  {
    state_list->num_of_retransmission = 0;
  }
}
