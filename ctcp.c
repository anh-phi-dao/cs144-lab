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
  long track_time;
};

/**
 * Linked list of connection states. Go through this in ctcp_timer() to
 * resubmit segments and tear down connections.
 */
static ctcp_state_t *state_list;

/* FIXME: Feel free to add as many helper functions as needed. Don't repeat
          code! Helper functions make the code clearer and cleaner. */
char buff[MAX_SEG_DATA_SIZE + 1];

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

  state->cfg = malloc(sizeof(ctcp_config_t));
  memcpy(state->cfg, cfg, sizeof(ctcp_config_t));
  state->cfg->send_window = MAX_SEG_IN_WINDOW;
  state->cfg->recv_window = MAX_SEG_IN_WINDOW;
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
  uint16_t len = segment->len;
  segment->ackno = htonl(segment->ackno);
  segment->seqno = htonl(segment->seqno);
  segment->len = htons(segment->len);
  segment->window = htons(segment->window);
  segment->flags = htonl(segment->flags);
  segment->cksum = 0;
  segment->cksum = cksum(segment, len);
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

    /*when meet an acked segment*/
    if (seg->ackno == seg->seqno + seg->len - sizeof(ctcp_segment_t))
    {
#ifdef DEBUG_UPDATE_SEND_BASE
      fprintf(stderr, "[INFO] Meet unacknowledg segment when updating send base with seqno =%d\n", seg->seqno);
#endif
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
  ctcp_segment_timer_t *timer = NULL;
#ifdef DEBUG_FIND_TIMER
  fprintf(stderr, "[INFO] Begin finding timer\n");
#endif
  while (track != NULL)
  {
    timer = (ctcp_segment_timer_t *)track->object;
    if (timer != NULL && timer->seqno == seqno)
    {
#ifdef DEBUG_FIND_TIMER
      fprintf(stderr, "[INFO] Found timer with seqno =%d\n", timer->seqno);
      fprintf(stderr, "[INFO] Timer with address =%p\n", timer);
#endif
      break;
    }
    track = track->next;
  }
  return timer;
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
  /*go through every segment that still exist in sender buffer*/
  while (track != NULL)
  {
    ctcp_segment_t *seg = (ctcp_segment_t *)track->object;
    /*When this segment is not acknowledged*/
    if (seg->ackno != seg->seqno + seg->len - sizeof(ctcp_segment_t))
    {
      /*check timer of corresponding unacknowledged segments*/
      ctcp_segment_timer_t *time_track = find_timer(state, seg->seqno);
      if (time_track == NULL)
      {
#ifdef DEBUG_RETRANSMISSION
        fprintf(stderr, "Can not find timer for unacknowledge segment with seqno %d\n", seg->seqno);
#endif
        track = track->next;
        continue;
      }
      /*if timeout has not not occured yet , switch to another packet*/
      long delta_time = current_time() - time_track->current_time;
      if (delta_time < state->cfg->rt_timeout)
      {

        track = track->next;
        continue;
      }
#ifdef DEBUG_RETRANSMISSION
      fprintf(stderr, "Retransmitting sequence with seqno %d\n", seg->seqno);
#endif
      /*if timeout has occurred, retransmit the segment if they are still inside the window*/
      require_transmit = THERE_ARE_SEGMENT_REQUIRE_RETRANSMISSION;
      time_track->current_time = current_time();
      memset(buff, 0, sizeof(buff));
      uint32_t new_seqno = seg->seqno + (seg->len - sizeof(ctcp_segment_t));
      if (seg->seqno >= state->send_base && new_seqno <= (state->send_base + state->cfg->send_window - MAX_SEG_DATA_SIZE))
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
  /*Increase this value if there are retransmissions*/
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
  if (track->prev != NULL)
  {
    track = track->prev;
    ll_add_after(buff, track, segment);
  }
  else
  {
    ll_add_front(buff, segment);
  }
}

/*They handle before change back to host*/
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
    read_bytes = conn_input(state->conn, buff, MAX_SEG_DATA_SIZE);
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
      /*if the created segment is still in sender window*/
      /*send the segment to receiver*/
      if (sent_segment->seqno >= state->send_base && new_seqno <= (state->send_base + state->cfg->send_window - MAX_SEG_DATA_SIZE))
      {
        uint16_t seg_len = sent_segment->len;
        /*update for later use of retransmission*/
        ctcp_segment_t *sent_seg = malloc(sent_segment->len);
        memcpy(sent_seg, sent_segment, sent_segment->len);
        segment_host_to_network(sent_seg);
#ifdef DEBUG_SENDER
        fprintf(stderr, "[INFO] Sender");
#endif
#ifdef DEBUG_SEGMENT

        print_hdr_ctcp(sent_seg);
#endif
        conn_send(state->conn, sent_seg, seg_len);
        sent_seg = free_ctcp_segment_t(sent_seg);
        state->nextseqno = new_seqno;
      }
    }
    /*When it detect an EOF, send a FIN and change the state->FIN_Close so the ctcp_timer() can destroy the connection*/
  } while (read_bytes > 0);
  if (read_bytes < 0)
  {
    if (state != NULL)
    {
      /*send a FIN*/
      if (state->FIN_Close == NORMAL_STATE)
      {
        send_FIN(state);
        fprintf(stderr, "[INFO] Write an EOF,sending FIN and closing connection\n");
        state->track_time = current_time();
        state->FIN_Close = FIN_SENT_OR_RECEIVED;
      }
    }
  }
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
  /* corrupted and truncated segment*/
  if (is_corrupt(segment) == 1)
  {
#ifdef DEBUG_CORRUPT
    fprintf(stderr, "[INFO] Corrupted segment\n");
#endif
    free(segment);
    return;
  }
  /*change back to host-byte-order*/
  segment_network_to_host(segment);
#ifdef DEBUF_SEGMENT_LEN
  fprintf(stderr, "[INFO] Len = %lu and segment->len = %d\n", len, segment->len);
#endif
  /*If receive a FIN signal*/
  /*send an acknowledgement*/
  /*Base on current state to change state and send another FIN*/
  if ((segment->flags & FIN) != 0)
  {
    send_acknowledgement_of_received_packet(state, segment);
    if (state->FIN_Close == NORMAL_STATE)
    {
      send_FIN(state);
      state->FIN_Close = FIN_SENT_OR_RECEIVED;
      state->track_time = current_time();
      fprintf(stderr, "[INFO] Received FIN, closing connection\n");
    }
    free(segment);
    return;
  }
  /*If recieve a packet or an acknowledgement*/
  else if ((segment->flags & ACK) != 0)
  {
/*on sender side when receiving acknowledgement*/
#ifdef DEBUG_SEGMENT
    fprintf(stderr, "[INFO] segment len =%d\n", segment->len);
#endif
    if (segment->len == sizeof(ctcp_segment_t))
    {
      /*If acknowledgement is inside window*/
      if (segment->ackno <= (state->send_base + state->cfg->send_window - MAX_SEG_DATA_SIZE))
      {
#ifdef DEBUG_SENDER
        fprintf(stderr, "[INFO] Incoming segment with ackno =%d is inside window\n", segment->ackno);
#endif
        /*use the segment->ackno to find its segment with corresponding sequence number*/
        ll_node_t *track = state->segments->head;
        /*fine the segment inside state->segments*/
        while (track != NULL)
        {
          ctcp_segment_t *sender_buff_segment = (ctcp_segment_t *)track->object;
          uint32_t expected_ackno = sender_buff_segment->seqno + sender_buff_segment->len - sizeof(ctcp_segment_t);
          /*if meet corresponding segment, acknowledge the segment */
          if (expected_ackno == segment->ackno)
          {
#ifdef DEBUG_INCOMING_ACKNOWLEDGEMENT
            fprintf(stderr, "[INFO] Found segment in buffer that corresponding to ack\n");
            fprintf(stderr, "[INFO] segment->ackno=%d buffed_seqno=%d expected_ackno=%d\n", segment->ackno, sender_buff_segment->seqno, expected_ackno);
            fprintf(stderr, "[INFO] state->sendbase=%d\n", state->send_base);
#endif
            /*if recieve an acknowledgemnt of an acknowledged segment, do nothing*/
            if (sender_buff_segment->ackno == segment->ackno)
            {
              break;
            }
            /*this will markS the segment become acknowledged*/
            /*A segment is acknowledged if its ackno!=1*/
            /*its ackno=seqno+len-20*/
            sender_buff_segment->ackno = segment->ackno;
            if (sender_buff_segment->seqno == state->send_base)
            {
              /*update send base and clean acknowledged segment before send base value*/
              update_send_base(state);
            }
            break;
          }
          track = track->next;
        }
      }
      free(segment);
    }
    else
    {
      /*on receiver side*/
      /*if recieved packet is inside window*/
      uint32_t next_seqno = segment->seqno + segment->len - sizeof(ctcp_segment_t);
      if (segment->seqno >= state->receive_base && next_seqno <= (state->receive_base + state->cfg->recv_window - MAX_SEG_DATA_SIZE))
      {
        /*send acknowledgement*/
        send_acknowledgement_of_received_packet(state, segment);
        /*if this segment does not exist inside receiver buffer*/
        /*Add this segment in order */
        if (find_segment_in_buffer(state->receive_segments, segment) == DID_NOT_FIND_SEGMENT_IN_BUFFER)
        {
          /*must add follow order*/
          add_to_buffer_with_order(state->receive_segments, segment);
        }
        /*if this packet has the sequence number which is equal to receive base*/
        /*output any packet that is exist in receiver base and any previously buffered and consecultively number packet*/
        /*the receive window is moved forward by the number of packets deliverd*/
        if (segment->seqno == state->receive_base)
        {
          ctcp_output(state);
        }
      }
      /*if receive a segment that belong to [rcv_base-N,rcv_base-1]*/
      /*this means it is still a correct packet*/
      /*only send acknowledgement because this packet is already received and acknowledged*/
      else if (segment->seqno >= (state->receive_base - state->cfg->recv_window) && next_seqno <= (state->receive_base - MAX_SEG_DATA_SIZE))
      {
        send_acknowledgement_of_received_packet(state, segment);
        free(segment);
      }
      /*Other wise, ignore the packet*/
      else
      {
        free(segment);
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
      /*when we reach to the last packer*/
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
        /*if next bufferd packet has a sequence number which is consecultive* to current segment's sequence number*/
        /*output the current packet */
        /*update the receive base*/
        /*delete the current packet*/
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

void deal_in_timer(ctcp_state_t *state)
{
  if (state == NULL)
  {
    return;
  }
  /*when the number of retransmission is greater than 5, this means that the connection has been destroyed*/
  /*Destroy the connection state*/
  if (state->num_of_retransmission >= 10)
  {
#ifdef DEBUG_RETRANSMISSION
    fprintf(stderr, "[ERROR] Too many retransmission, destroying the connection\n");
#endif
    ctcp_destroy(state);
    return;
  }
  /*when host reach to this state, wait for x miliseconds and destroy the connection*/
  if (state->FIN_Close == FIN_SENT_OR_RECEIVED)
  {

    if ((current_time() - state->track_time) > 5000)
    {
#ifdef DEBUG_FIN_SIGNAL
      fprintf(stderr, "[INFO] Connection has been destroyed due to FIN signal\n");
      print_state_number(state);
#endif
      ctcp_destroy(state);
    }
    return;
  }

  /*if there are unacknowledged segment, retransmit the segment*/
  ll_node_t *track = state->segments->head;

  if (track != NULL)
  {
    retransmit_segments(state);
  }
  else
  {
    state->num_of_retransmission = 0;
  }
}

void ctcp_timer()
{
  /* FIXME */
  /* FIXME */
  ctcp_state_t *state = state_list;
  while (state != NULL)
  {
    /* code */
    deal_in_timer(state);
    state = state->next;
  }
}
